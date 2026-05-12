package admin

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v4"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

type socialUsers struct {
	logger *logrus.Entry
	db     *lion.Client

	aesKey     []byte
	privateKey *rsa.PrivateKey

	ProviderName string
	AuthProvider *lion.AuthProviders

	// 解析后的类型特有配置（根据 provider_type 二选一）
	oauthCfg *oauthConfigData
	ldapCfg  *ldapConfigData
	// 解密后的敏感凭证（LDAP 为 bind_password，OAuth2 系为 client_secret）
	secret string

	Groups []string `json:"groups"`
}

func newSocialUsers(ctx context.Context, logger *logrus.Entry, aesKey []byte, db *lion.Client, providerName string) (*socialUsers, error) {
	ap, err := db.AuthProviders.Query().
		Select(
			authproviders.FieldID,
			authproviders.FieldCode,
			authproviders.FieldProviderType,
			authproviders.FieldProviderStatus,
			authproviders.FieldConfig,
			authproviders.FieldSecretEncrypted,
		).
		Where(
			authproviders.CodeEQ(providerName),
		).Only(ctx)
	if err != nil {
		return nil, err
	}

	sk, err := db.Credentials.Query().
		Select(credentials.FieldPrivateKeyEncrypted).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	derBytes, err := crypto.DecryptAES(aesKey, sk.PrivateKeyEncrypted)
	if err != nil {
		return nil, err
	}

	// 解析为 PKCS#1 格式
	privateKey, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#1 private key: %v", err)
	}

	s := &socialUsers{
		logger:       logger,
		db:           db,
		aesKey:       aesKey,
		privateKey:   privateKey,
		ProviderName: providerName,
		AuthProvider: ap,
	}

	// 根据 provider_type 解析 config JSON 和解密凭证
	switch adminv1.AuthProvider_Type(ap.ProviderType) {
	case adminv1.AuthProvider_LDAP:
		var ldapCfg ldapConfigData
		if len(ap.Config) > 0 {
			if err := json.Unmarshal(ap.Config, &ldapCfg); err != nil {
				return nil, fmt.Errorf("parse ldap config: %w", err)
			}
		}
		s.ldapCfg = &ldapCfg
		if len(ap.SecretEncrypted) > 0 {
			decrypted, decErr := crypto.DecryptAES(aesKey, ap.SecretEncrypted)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt ldap secret: %w", decErr)
			}
			s.secret = string(decrypted)
		}

	case adminv1.AuthProvider_OIDC, adminv1.AuthProvider_OAUTH2,
		adminv1.AuthProvider_GITHUB, adminv1.AuthProvider_GOOGLE,
		adminv1.AuthProvider_WECHAT:
		cfg, secret, err := parseOAuthConfigFromDB(ap, aesKey)
		if err != nil {
			return nil, fmt.Errorf("parse oauth provider config: %w", err)
		}
		s.oauthCfg = cfg
		s.secret = secret

	case adminv1.AuthProvider_LOCAL:
		// LOCAL 类型无额外配置，仅解密凭证（如有）
		if len(ap.SecretEncrypted) > 0 {
			decrypted, decErr := crypto.DecryptAES(aesKey, ap.SecretEncrypted)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt local secret: %w", decErr)
			}
			s.secret = string(decrypted)
		}
	}

	return s, nil
}

// Exchange 根据客户端上报的 code 进行二次验证返回 access_token
func (s *socialUsers) Exchange(ctx context.Context, code string) (string, error) {
	accessToken := ""

	idToken := &auth.IDTokenClaims{}

	switch adminv1.AuthProvider_Type(s.AuthProvider.ProviderType) {
	case adminv1.AuthProvider_LOCAL:

	case adminv1.AuthProvider_WECHAT:
		resp, err := s.weixinExchange(ctx, code)
		if err != nil {
			return "", err
		}

		userID, err := s.upsertUserWechat(ctx, resp)
		if err != nil {
			return "", err
		}

		if err = s.setUserRoles(ctx, userID); err != nil {
			return "", err
		}

		// 填充 idToken 内容
		idToken.SetSubject(strconv.Itoa(userID))
		idToken.SetGroups(s.Groups)

		accessToken, err = idToken.GetAccessToken(resp.SessionKey)
		if err != nil {
			return accessToken, err
		}

		return accessToken, nil
	case adminv1.AuthProvider_OIDC:
		oauth2Token, err := s.oauth2Exchange(ctx, code)
		if err != nil {
			return accessToken, err
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			return accessToken, fmt.Errorf("get auth providers failed")
		}

		// 填充 idToken 内容
		_, err = jwt.ParseWithClaims(rawIDToken, idToken, func(token *jwt.Token) (interface{}, error) {
			return nil, nil
		})
		idToken.SetExpiresAt(oauth2Token.ExpiresIn)

		// 判断是否已存在数据库中
		userID, err := s.upsertUserOIDC(ctx, oauth2Token, idToken)
		if err != nil {
			return accessToken, err
		}

		if err = s.setUserRoles(ctx, userID); err != nil {
			return "", err
		}

		// 填充 idToken 内容
		idToken.SetSubject(strconv.Itoa(userID))
		idToken.SetGroups(s.Groups)

		// 生成 jwt 返回客户端
		accessToken, err = idToken.GetAccessTokenRSA(s.privateKey)
		if err != nil {
			return accessToken, err
		}

	case adminv1.AuthProvider_OAUTH2, adminv1.AuthProvider_GITHUB, adminv1.AuthProvider_GOOGLE:
		oauth2Token, err := s.oauth2Exchange(ctx, code)
		if err != nil {
			return accessToken, err
		}

		userinfo, err := s.oauth2Userinfo(ctx, oauth2Token)
		if err != nil {
			return accessToken, err
		}

		idField := "sub"
		nameField := "name"
		emailField := "email"
		if s.oauthCfg != nil {
			if s.oauthCfg.UserinfoIdField != "" {
				idField = s.oauthCfg.UserinfoIdField
			}
			if s.oauthCfg.UserinfoNameField != "" {
				nameField = s.oauthCfg.UserinfoNameField
			}
			if s.oauthCfg.UserinfoEmailField != "" {
				emailField = s.oauthCfg.UserinfoEmailField
			}
		}
		if adminv1.AuthProvider_Type(s.AuthProvider.ProviderType) == adminv1.AuthProvider_GITHUB {
			// GitHub userinfo 默认主键为 id，用户名通常是 login。
			idField = "id"
			nameField = "login"
			emailField = "email"
		}

		providerUserID := getMapString(userinfo, idField)
		if providerUserID == "" {
			providerUserID = getMapString(userinfo, "sub")
		}
		if providerUserID == "" {
			return accessToken, fmt.Errorf("oauth userinfo missing id field: %s", idField)
		}

		username := getMapString(userinfo, nameField)
		if username == "" {
			username = providerUserID
		}
		email := getMapString(userinfo, emailField)

		idToken = &auth.IDTokenClaims{
			Username:      username,
			Nickname:      username,
			Email:         email,
			EmailVerified: email != "",
		}
		idToken.SetSubject(providerUserID)

		expiresIn := int64(3600)
		if !oauth2Token.Expiry.IsZero() {
			if sec := int64(time.Until(oauth2Token.Expiry).Seconds()); sec > 0 {
				expiresIn = sec
			}
		}
		idToken.SetExpiresAt(expiresIn)

		userID, err := s.upsertUserOIDC(ctx, oauth2Token, idToken)
		if err != nil {
			return accessToken, err
		}

		if err = s.setUserRoles(ctx, userID); err != nil {
			return "", err
		}

		idToken.SetSubject(strconv.Itoa(userID))
		idToken.SetGroups(s.Groups)

		accessToken, err = idToken.GetAccessTokenRSA(s.privateKey)
		if err != nil {
			return accessToken, err
		}
	}

	return accessToken, nil
}

func getMapString(m map[string]interface{}, key string) string {
	if m == nil || key == "" {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch vv := v.(type) {
	case string:
		return strings.TrimSpace(vv)
	case float64:
		return strconv.FormatInt(int64(vv), 10)
	case json.Number:
		return vv.String()
	default:
		return fmt.Sprintf("%v", vv)
	}
}

// passwordCheckResult 密码校验结果
type passwordCheckResult struct {
	AccessToken string
	OK          bool
	MfaEnabled  bool
	UserID      int
	Username    string
}

func (s *socialUsers) PasswordCheck(ctx context.Context, username, password string) (*passwordCheckResult, error) {
	switch adminv1.AuthProvider_Type(s.AuthProvider.ProviderType) {
	case adminv1.AuthProvider_LOCAL:
		return s.PasswordCheckLocal(ctx, username, password)
	case adminv1.AuthProvider_LDAP:
		return s.PasswordCheckLDAP(ctx, username, password)
	default:
		return nil, fmt.Errorf("password check does not support provider type: %s", adminv1.AuthProvider_Type(s.AuthProvider.ProviderType).String())
	}
}

func (s *socialUsers) PasswordCheckLocal(ctx context.Context, username, passwordHash string) (*passwordCheckResult, error) {
	u, err := s.db.Users.Query().
		Select(
			users.FieldID,
			users.FieldUsername,
			users.FieldNickname,
		).
		Where(
			users.UsernameEQ(username),
			users.UserStatusEQ(int(adminv1.User_ACTIVE.Number())),
		).
		WithLionUserIdentities(func(q *lion.UserIdentitiesQuery) {
			q.Select(
				useridentities.FieldPasswordHash,
				useridentities.FieldMfaEnabled,
			)
		}).
		Only(ctx)
	if err != nil {
		return &passwordCheckResult{}, err
	}

	if len(u.Edges.LionUserIdentities) == 0 {
		return &passwordCheckResult{}, nil
	}

	identity := u.Edges.LionUserIdentities[0]
	if err := crypto.BcryptCompare(identity.PasswordHash, passwordHash); err != nil {
		return &passwordCheckResult{}, nil
	}

	if identity.MfaEnabled {
		return &passwordCheckResult{
			OK:         true,
			MfaEnabled: true,
			UserID:     u.ID,
			Username:   u.Username,
		}, nil
	}

	tk, ok, err := s.issueAccessTokenForUser(ctx, u)
	if err != nil {
		return &passwordCheckResult{}, err
	}
	return &passwordCheckResult{
		AccessToken: tk,
		OK:          ok,
		UserID:      u.ID,
		Username:    u.Username,
	}, nil
}

func (s *socialUsers) PasswordCheckLDAP(ctx context.Context, username, passwordPlain string) (*passwordCheckResult, error) {
	if strings.TrimSpace(username) == "" || passwordPlain == "" {
		s.logger.Warnf("ldap login skipped: empty username or password, provider=%s", s.ProviderName)
		return &passwordCheckResult{}, nil
	}
	if s.ldapCfg == nil {
		s.logger.Errorf("ldap login failed: ldap config not initialized, provider=%s", s.ProviderName)
		return nil, fmt.Errorf("ldap config not initialized")
	}
	s.logger.Infof(
		"ldap login start: provider=%s username=%s host=%s port=%d use_tls=%t start_tls=%t",
		s.ProviderName,
		username,
		strings.TrimSpace(s.ldapCfg.Host),
		s.ldapCfg.Port,
		s.ldapCfg.UseTLS,
		s.ldapCfg.StartTLS,
	)

	conn, err := s.newLDAPConn()
	if err != nil {
		s.logger.Errorf("ldap login failed: connect failed, provider=%s err=%v", s.ProviderName, err)
		return nil, err
	}
	defer conn.Close()

	// 管理员绑定用于搜索用户 DN，未配置时允许匿名搜索。
	bindDN := strings.TrimSpace(s.ldapCfg.BindDN)
	if bindDN != "" || s.secret != "" {
		if err := conn.Bind(bindDN, s.secret); err != nil {
			s.logger.Errorf(
				"ldap login failed: service bind failed, provider=%s bind_dn=%s err=%v",
				s.ProviderName,
				maskLDAPDN(bindDN),
				err,
			)
			return nil, fmt.Errorf("ldap bind service account failed")
		}
		s.logger.Infof("ldap login debug: service bind success, provider=%s bind_dn=%s", s.ProviderName, maskLDAPDN(bindDN))
	}

	userDN, resolvedUsername, err := s.findLDAPUserDN(conn, username)
	if err != nil {
		s.logger.Errorf("ldap login failed: user search failed, provider=%s username=%s err=%v", s.ProviderName, username, err)
		return nil, err
	}
	if userDN == "" {
		s.logger.Warnf("ldap login failed: user not found in ldap, provider=%s username=%s", s.ProviderName, username)
		return &passwordCheckResult{}, nil
	}
	s.logger.Infof(
		"ldap login debug: user found, provider=%s username=%s resolved_username=%s user_dn=%s",
		s.ProviderName,
		username,
		resolvedUsername,
		maskLDAPDN(userDN),
	)

	// 用户口令校验：二次 bind。
	if err := conn.Bind(userDN, passwordPlain); err != nil {
		s.logger.Warnf(
			"ldap login failed: user bind failed, provider=%s username=%s user_dn=%s err=%v",
			s.ProviderName,
			username,
			maskLDAPDN(userDN),
			err,
		)
		return &passwordCheckResult{}, nil
	}
	s.logger.Infof("ldap login debug: user bind success, provider=%s username=%s user_dn=%s", s.ProviderName, username, maskLDAPDN(userDN))

	ldapIdentity, err := s.db.UserIdentities.Query().
		Select(
			useridentities.FieldID,
			useridentities.FieldUserID,
			useridentities.FieldMfaEnabled,
		).
		Where(
			useridentities.ProviderIDEQ(s.AuthProvider.ID),
			useridentities.ProviderUserIDEQ(userDN),
		).
		Only(ctx)
	if err != nil && !lion.IsNotFound(err) {
		s.logger.Errorf(
			"ldap login failed: query identity error, provider=%s user_dn=%s err=%v",
			s.ProviderName,
			maskLDAPDN(userDN),
			err,
		)
		return nil, err
	}

	var localUserID int
	var ldapMfaEnabled bool
	if ldapIdentity != nil {
		localUserID = ldapIdentity.UserID
		ldapMfaEnabled = ldapIdentity.MfaEnabled
		s.logger.Infof(
			"ldap login debug: identity hit, provider=%s user_dn=%s local_user_id=%d",
			s.ProviderName,
			maskLDAPDN(userDN),
			localUserID,
		)
	} else {
		s.logger.Warnf(
			"ldap login debug: identity miss, start auto provision, provider=%s username=%s resolved_username=%s user_dn=%s",
			s.ProviderName,
			username,
			resolvedUsername,
			maskLDAPDN(userDN),
		)
		localUserID, err = s.provisionLDAPUserOnFirstLogin(ctx, userDN, resolvedUsername)
		if err != nil {
			s.logger.Errorf(
				"ldap login failed: auto provision error, provider=%s username=%s resolved_username=%s user_dn=%s err=%v",
				s.ProviderName,
				username,
				resolvedUsername,
				maskLDAPDN(userDN),
				err,
			)
			return nil, err
		}
		s.logger.Infof(
			"ldap login debug: auto provision success, provider=%s user_dn=%s local_user_id=%d",
			s.ProviderName,
			maskLDAPDN(userDN),
			localUserID,
		)
	}

	userEntity, err := s.db.Users.Query().
		Select(
			users.FieldID,
			users.FieldUsername,
			users.FieldNickname,
		).
		Where(
			users.IDEQ(localUserID),
			users.UserStatusEQ(int(adminv1.User_ACTIVE.Number())),
		).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			s.logger.Warnf(
				"ldap login failed: local user not active or not found, provider=%s local_user_id=%d user_dn=%s",
				s.ProviderName,
				localUserID,
				maskLDAPDN(userDN),
			)
			return &passwordCheckResult{}, nil
		}
		s.logger.Errorf(
			"ldap login failed: local user query error, provider=%s local_user_id=%d err=%v",
			s.ProviderName,
			localUserID,
			err,
		)
		return nil, err
	}

	if ldapMfaEnabled {
		return &passwordCheckResult{
			OK:         true,
			MfaEnabled: true,
			UserID:     userEntity.ID,
			Username:   userEntity.Username,
		}, nil
	}

	tk, ok, err := s.issueAccessTokenForUser(ctx, userEntity)
	if err != nil {
		return nil, err
	}
	return &passwordCheckResult{
		AccessToken: tk,
		OK:          ok,
		UserID:      userEntity.ID,
		Username:    userEntity.Username,
	}, nil
}

func (s *socialUsers) provisionLDAPUserOnFirstLogin(ctx context.Context, userDN, ldapUsername string) (int, error) {
	tx, err := s.db.Tx(ctx)
	if err != nil {
		return 0, err
	}

	baseUsername := buildLDAPLocalUsernameBase(s.ProviderName, ldapUsername)
	localUsername, err := findAvailableUsername(ctx, tx, baseUsername)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	newUser, err := tx.Users.Create().
		SetUsername(localUsername).
		SetNickname(ldapUsername).
		SetUserStatus(int(adminv1.User_ACTIVE.Number())).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	_, err = tx.UserIdentities.Create().
		SetUserID(newUser.ID).
		SetProviderID(s.AuthProvider.ID).
		SetProviderUserID(userDN).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newUser.ID, nil
}

func buildLDAPLocalUsernameBase(providerCode, ldapUsername string) string {
	safeProvider := sanitizeUsernamePart(providerCode)
	if safeProvider == "" {
		safeProvider = "ldap"
	}
	safeUsername := sanitizeUsernamePart(ldapUsername)
	if safeUsername == "" {
		safeUsername = "user"
	}
	return strings.ToLower(fmt.Sprintf("%s_%s", safeProvider, safeUsername))
}

func sanitizeUsernamePart(raw string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "" {
		return ""
	}
	re := regexp.MustCompile(`[^a-z0-9_]+`)
	v = re.ReplaceAllString(v, "_")
	v = strings.Trim(v, "_")
	return v
}

func findAvailableUsername(ctx context.Context, tx *lion.Tx, base string) (string, error) {
	const maxTry = 100
	for i := 0; i < maxTry; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s_%d", base, i+1)
		}
		_, err := tx.Users.Query().Where(users.UsernameEQ(candidate)).OnlyID(ctx)
		if lion.IsNotFound(err) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("unable to allocate available username for base=%s", base)
}

func (s *socialUsers) issueAccessTokenForUser(ctx context.Context, u *lion.Users) (string, bool, error) {
	if err := s.setUserRoles(ctx, u.ID); err != nil {
	}

	idToken := &auth.IDTokenClaims{
		Username: u.Username,
		Nickname: u.Nickname,
	}
	// 填充 idToken 内容
	idToken.SetSubject(strconv.Itoa(u.ID))
	idToken.SetGroups(s.Groups)
	idToken.SetExpiresAt(24 * 60 * 60)
	idToken.SetEmail(fmt.Sprintf("%v@localhost", u.Username))

	// 生成 jwt 返回客户端
	accessToken, err := idToken.GetAccessTokenRSA(s.privateKey)
	if err != nil {
		return "", false, err
	}

	return accessToken, true, nil
}

func (s *socialUsers) newLDAPConn() (*ldap.Conn, error) {
	host := strings.TrimSpace(s.ldapCfg.Host)
	if host == "" {
		return nil, fmt.Errorf("ldap host is required")
	}

	port := s.ldapCfg.Port
	if port == 0 {
		if s.ldapCfg.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.ldapCfg.InsecureSkipVerify,
		ServerName:         host,
	}

	var (
		conn *ldap.Conn
		err  error
	)
	if s.ldapCfg.UseTLS {
		conn, err = ldap.DialURL("ldaps://"+address, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL("ldap://" + address)
	}
	if err != nil {
		return nil, err
	}

	conn.SetTimeout(10 * time.Second)
	if !s.ldapCfg.UseTLS && s.ldapCfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func (s *socialUsers) findLDAPUserDN(conn *ldap.Conn, username string) (string, string, error) {
	searchBase := strings.TrimSpace(s.ldapCfg.UserSearchBase)
	if searchBase == "" {
		s.logger.Errorf("ldap search failed: empty user_search_base, provider=%s username=%s", s.ProviderName, username)
		return "", "", fmt.Errorf("ldap user_search_base is required")
	}

	usernameAttribute := strings.TrimSpace(s.ldapCfg.UsernameAttribute)
	if usernameAttribute == "" {
		usernameAttribute = "uid"
	}

	escapedUsername := ldap.EscapeFilter(username)
	filterTemplate := strings.TrimSpace(s.ldapCfg.UserSearchFilter)
	var filter string
	switch {
	case filterTemplate == "":
		filter = fmt.Sprintf("(%s=%s)", usernameAttribute, escapedUsername)
	case strings.Contains(filterTemplate, "%s"):
		filter = fmt.Sprintf(filterTemplate, escapedUsername)
	case strings.Contains(filterTemplate, "{username}"):
		filter = strings.ReplaceAll(filterTemplate, "{username}", escapedUsername)
	default:
		filter = fmt.Sprintf("(&%s(%s=%s))", filterTemplate, usernameAttribute, escapedUsername)
	}
	s.logger.Infof(
		"ldap search debug: provider=%s username=%s search_base=%s username_attr=%s filter=%s",
		s.ProviderName,
		username,
		searchBase,
		usernameAttribute,
		filter,
	)

	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		0,
		false,
		filter,
		[]string{usernameAttribute},
		nil,
	)
	searchResp, err := conn.Search(searchReq)
	if err != nil {
		s.logger.Errorf("ldap search failed: provider=%s username=%s err=%v", s.ProviderName, username, err)
		return "", "", err
	}
	s.logger.Infof(
		"ldap search debug: provider=%s username=%s entry_count=%d",
		s.ProviderName,
		username,
		len(searchResp.Entries),
	)
	if len(searchResp.Entries) == 0 {
		return "", "", nil
	}
	if len(searchResp.Entries) > 1 {
		s.logger.Warnf("ldap search failed: multiple entries, provider=%s username=%s entry_count=%d", s.ProviderName, username, len(searchResp.Entries))
		return "", "", fmt.Errorf("ldap user search returned multiple entries")
	}

	entry := searchResp.Entries[0]
	resolvedUsername := strings.TrimSpace(entry.GetAttributeValue(usernameAttribute))
	if resolvedUsername == "" {
		resolvedUsername = username
	}

	return entry.DN, resolvedUsername, nil
}

func maskLDAPDN(dn string) string {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return ""
	}
	if len(dn) <= 16 {
		return dn
	}
	return dn[:8] + "...(masked)"
}

func (s *socialUsers) GetAccessToken(expiresIn int32, appid string) {

}

func (s *socialUsers) upsertUserOIDC(ctx context.Context, oauth2Token *oauth2.Token, idToken *auth.IDTokenClaims) (int, error) {
	existIdentity, err := s.db.UserIdentities.Query().
		Where(
			useridentities.ProviderID(s.AuthProvider.ID),
			useridentities.ProviderUserIDEQ(idToken.Subject),
		).
		Select(useridentities.FieldID, useridentities.FieldUserID).
		Only(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return 0, err
	}

	var existUserID int
	if existIdentity != nil {
		existUserID = existIdentity.UserID
	}

	if existUserID == 0 && lion.IsNotFound(err) {
		// TODO; 新增用户，preferred username 如何定义，开启事务
		// 规范：provider_name_email_prefix
		username := strings.ToLower(fmt.Sprintf("%v_%v", s.ProviderName, idToken.Subject))

		// 首先确保 "lion_users" 不存在这个用户，开启一个事务
		tx, err := s.db.Tx(ctx)
		if err != nil {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		_, err = tx.Users.Query().Where(users.UsernameEQ(username)).OnlyID(ctx)
		if !lion.IsNotFound(err) {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		var emailEnc []byte
		emailEnc, err = crypto.EncryptAES(s.aesKey, []byte(idToken.Email))
		if err != nil {
			// TODO;
		}

		newUser, err := tx.Users.Create().
			SetUsername(username).
			SetEmailEncrypted(emailEnc).
			SetEmailVerified(idToken.EmailVerified).
			SetEmailHash(crypto.SHA256([]byte(idToken.Email))).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, to save err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		var accessTokenEnc, refreshTokenEnc []byte
		if oauth2Token.AccessToken != "" {
			accessTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.AccessToken))
		}
		if oauth2Token.RefreshToken != "" {
			refreshTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.RefreshToken))
		}

		_, err = tx.UserIdentities.Create().
			SetUserID(newUser.ID).
			SetProviderID(s.AuthProvider.ID).
			SetProviderUserID(idToken.Subject).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc).
			SetTokenExpiresAt(oauth2Token.Expiry).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		existUserID = newUser.ID

		_ = tx.Commit()
	} else {
		var accessTokenEnc, refreshTokenEnc []byte
		if oauth2Token.AccessToken != "" {
			accessTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.AccessToken))
		}
		if oauth2Token.RefreshToken != "" {
			refreshTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.RefreshToken))
		}

		s.db.UserIdentities.Update().
			Where(useridentities.IDEQ(existIdentity.ID)).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc).
			SetTokenExpiresAt(oauth2Token.Expiry)

		// 设置用户组
	}

	return existUserID, nil
}

func (s *socialUsers) oauth2Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	if s.oauthCfg == nil {
		return nil, fmt.Errorf("oauth config not initialized")
	}

	endpoint := oauth2.Endpoint{}
	if s.oauthCfg.Issuer != "" {
		op, err := oidc.NewProvider(ctx, s.oauthCfg.Issuer)
		if err != nil {
			return nil, err
		}
		endpoint = op.Endpoint()
	} else {
		endpoint = oauth2.Endpoint{
			AuthURL:  s.oauthCfg.AuthorizationEndpoint,
			TokenURL: s.oauthCfg.TokenEndpoint,
		}

		// GitHub 场景默认端点兜底，避免必须配置 issuer。
		if adminv1.AuthProvider_Type(s.AuthProvider.ProviderType) == adminv1.AuthProvider_GITHUB {
			if endpoint.AuthURL == "" {
				endpoint.AuthURL = "https://github.com/login/oauth/authorize"
			}
			if endpoint.TokenURL == "" {
				endpoint.TokenURL = "https://github.com/login/oauth/access_token"
			}
		}
		if endpoint.AuthURL == "" || endpoint.TokenURL == "" {
			return nil, fmt.Errorf("oauth endpoints not configured: authorization_endpoint/token_endpoint")
		}
	}

	oauth2Config := oauth2.Config{
		ClientID:     s.oauthCfg.ClientID,
		ClientSecret: s.secret,
		Endpoint:     endpoint,
		Scopes:       s.oauthCfg.Scopes,
		RedirectURL:  s.oauthCfg.RedirectURI,
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *socialUsers) oauth2Userinfo(ctx context.Context, oauth2Token *oauth2.Token) (map[string]interface{}, error) {
	if s.oauthCfg == nil {
		return nil, fmt.Errorf("oauth config not initialized")
	}
	if oauth2Token == nil || oauth2Token.AccessToken == "" {
		return nil, fmt.Errorf("oauth access token is empty")
	}

	userinfoEndpoint := s.oauthCfg.UserinfoEndpoint
	if userinfoEndpoint == "" && adminv1.AuthProvider_Type(s.AuthProvider.ProviderType) == adminv1.AuthProvider_GITHUB {
		apiURL := strings.TrimSuffix(s.oauthCfg.ApiURL, "/")
		if apiURL == "" {
			apiURL = "https://api.github.com"
		}
		userinfoEndpoint = apiURL + "/user"
	}
	if userinfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+oauth2Token.AccessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo request failed: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	userinfo := map[string]interface{}{}
	if err = json.Unmarshal(body, &userinfo); err != nil {
		return nil, fmt.Errorf("unmarshal userinfo: %w", err)
	}

	// GitHub 在 /user 可能拿不到公开邮箱，补查 /user/emails。
	if adminv1.AuthProvider_Type(s.AuthProvider.ProviderType) == adminv1.AuthProvider_GITHUB && getMapString(userinfo, "email") == "" {
		if email := s.githubPrimaryEmail(ctx, oauth2Token.AccessToken); email != "" {
			userinfo["email"] = email
		}
	}

	return userinfo, nil
}

func (s *socialUsers) githubPrimaryEmail(ctx context.Context, accessToken string) string {
	apiURL := strings.TrimSuffix(s.oauthCfg.ApiURL, "/")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/user/emails", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err = json.Unmarshal(body, &emails); err != nil {
		return ""
	}

	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			return e.Email
		}
	}
	for _, e := range emails {
		if e.Verified && e.Email != "" {
			return e.Email
		}
	}
	for _, e := range emails {
		if e.Primary && e.Email != "" {
			return e.Email
		}
	}
	if len(emails) > 0 {
		return emails[0].Email
	}
	return ""
}

func (s *socialUsers) weixinExchange(ctx context.Context, code string) (*wechatCode2SessionResponse, error) {
	if s.oauthCfg == nil {
		return nil, fmt.Errorf("oauth config not initialized")
	}

	wx := newWechatOpen(s.logger, s.oauthCfg.ClientID, s.secret)
	return wx.code2Session(s.oauthCfg.AuthorizationEndpoint, code)
}

func (s *socialUsers) upsertUserWechat(ctx context.Context, resp *wechatCode2SessionResponse) (int, error) {
	existIdentity, err := s.db.UserIdentities.Query().
		Where(
			useridentities.ProviderIDEQ(s.AuthProvider.ID),
			useridentities.ProviderUserIDEQ(resp.Openid),
		).
		Select(useridentities.FieldID, useridentities.FieldUserID).
		Only(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return 0, err
	}

	var existUserID int
	if existIdentity != nil {
		existUserID = existIdentity.UserID
	}

	if existUserID == 0 && lion.IsNotFound(err) {
		// TODO; 新增用户，preferred username 如何定义，开启事务
		// 规范：provider_name_email_prefix
		username := strings.ToLower(fmt.Sprintf("%v_%v", s.ProviderName, resp.Openid))

		// 首先确保 "lion_users" 不存在这个用户，开启一个事务
		tx, err := s.db.Tx(ctx)
		if err != nil {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		_, err = tx.Users.Query().Where(users.UsernameEQ(username)).OnlyID(ctx)
		if !lion.IsNotFound(err) {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		/*
			var emailEnc []byte
			emailEnc, err = crypto.EncryptAES(s.aesKey, []byte(idToken.Email))
			if err != nil {
				// TODO;
			}
		*/

		newUser, err := tx.Users.Create().
			SetUsername(username).
			//SetEmailEncrypted(emailEnc).
			//SetEmailVerified(idToken.EmailVerified).
			//SetEmailHash(crypto.SHA256([]byte(idToken.Email))).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		var accessTokenEnc, refreshTokenEnc []byte
		if resp.SessionKey != "" {
			accessTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(resp.SessionKey))
			refreshTokenEnc = accessTokenEnc
		}

		_, err = tx.UserIdentities.Create().
			SetUserID(newUser.ID).
			SetProviderID(s.AuthProvider.ID).
			SetProviderUserID(resp.Openid).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc).
			//SetTokenExpiresAt(oauth2Token.Expiry).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		existUserID = newUser.ID

		_ = tx.Commit()
	}

	return existUserID, nil
}

func (s *socialUsers) setUserRoles(ctx context.Context, userID int) error {
	roleIDs, err := effectiveRoleIDsForUser(ctx, s.db, userID)
	if err != nil {
		return err
	}
	roleCodes, err := roleCodesForIDs(ctx, s.db, roleIDs)
	if err != nil {
		return err
	}
	s.Groups = append(s.Groups, roleCodes...)

	return nil
}
