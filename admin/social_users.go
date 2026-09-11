package admin

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
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
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"

	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

type socialUsers struct {
	logger *logrus.Entry
	db     *lion.Client

	aesKey     []byte
	privateKey *rsa.PrivateKey
	// kid 是当前签名密钥的 code，写入 JWT header，
	// 供验证端从 JWKS 中匹配对应的公钥。多密钥轮换场景下不可缺失。
	kid string

	ProviderName string
	AuthProvider *lion.AuthProviders

	// 解析后的类型特有配置（根据 provider_type 二选一）
	oauthCfg *oauthConfigData
	ldapCfg  *ldapConfigData
	// 解密后的敏感凭证（LDAP 为 bind_password，OAuth2 系为 client_secret）
	secret string

	issuanceContext AccessTokenIssuanceContext
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
			authproviders.DeletedAtIsNil(),
		).Only(ctx)
	if err != nil {
		return nil, err
	}

	privateKey, kid, err := loadAccessTokenRSAKey(ctx, db, aesKey)
	if err != nil {
		return nil, err
	}

	s := &socialUsers{
		logger:       logger,
		db:           db,
		aesKey:       aesKey,
		privateKey:   privateKey,
		kid:          kid,
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

		accessToken, _, err = s.issueAccessTokenForUserID(ctx, userID)
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

		providerClaims, err := s.verifyOIDCIDToken(ctx, rawIDToken)
		if err != nil {
			return accessToken, err
		}
		profile := externalUserClaimsFromIDToken(providerClaims)

		// 判断是否已存在数据库中
		userID, err := s.upsertUserOIDC(ctx, oauth2Token, profile)
		if err != nil {
			return accessToken, err
		}

		accessToken, _, err = s.issueAccessTokenForUserID(ctx, userID)
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

		profile := externalUserClaims{
			ProviderSubject:     providerUserID,
			Username:            username,
			PreferredUsername:   username,
			Nickname:            username,
			Email:               email,
			EmailVerified:       getMapBool(userinfo, "email_verified"),
			PhoneNumber:         getMapString(userinfo, "phone_number"),
			PhoneNumberVerified: getMapBool(userinfo, "phone_number_verified"),
		}

		userID, err := s.upsertUserOIDC(ctx, oauth2Token, profile)
		if err != nil {
			return accessToken, err
		}

		accessToken, _, err = s.issueAccessTokenForUserID(ctx, userID)
		if err != nil {
			return accessToken, err
		}
	}

	return accessToken, nil
}

type externalUserClaims struct {
	ProviderSubject     string
	Username            string
	PreferredUsername   string
	Nickname            string
	Email               string
	EmailVerified       bool
	PhoneNumber         string
	PhoneNumberVerified bool
}

func externalUserClaimsFromIDToken(claims *auth.IDTokenClaims) externalUserClaims {
	preferredUsername := strings.TrimSpace(claims.PreferredUsername)
	username := preferredUsername
	if username == "" {
		// 仅兼容旧 provider token 中的自定义 username claim。
		username = strings.TrimSpace(claims.Username)
	}
	if username == "" {
		username = claims.Subject
	}

	return externalUserClaims{
		ProviderSubject:     claims.Subject,
		Username:            username,
		PreferredUsername:   preferredUsername,
		Nickname:            claims.Nickname,
		Email:               claims.Email,
		EmailVerified:       claims.EmailVerified,
		PhoneNumber:         claims.PhoneNumber,
		PhoneNumberVerified: claims.PhoneNumberVerified,
	}
}

func (s *socialUsers) verifyOIDCIDToken(ctx context.Context, rawIDToken string) (*auth.IDTokenClaims, error) {
	if s.oauthCfg == nil {
		return nil, fmt.Errorf("oauth config not initialized")
	}
	if strings.TrimSpace(s.oauthCfg.Issuer) == "" {
		return nil, fmt.Errorf("oidc issuer is required")
	}
	if strings.TrimSpace(s.oauthCfg.ClientID) == "" {
		return nil, fmt.Errorf("oidc client_id is required")
	}

	provider, err := oidc.NewProvider(ctx, s.oauthCfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}
	verifiedToken, err := provider.Verifier(&oidc.Config{ClientID: s.oauthCfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify oidc id_token: %w", err)
	}

	claims := &auth.IDTokenClaims{}
	if err := verifiedToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("decode oidc id_token claims: %w", err)
	}
	return claims, nil
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

func getMapBool(m map[string]interface{}, key string) bool {
	if m == nil || key == "" {
		return false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	verified, ok := v.(bool)
	return ok && verified
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
			users.DeletedAtIsNil(),
		).
		WithLionUserIdentities(func(q *lion.UserIdentitiesQuery) {
			q.Select(
				useridentities.FieldID,
				useridentities.FieldPasswordHash,
			).Where(useridentities.ProviderIDEQ(s.AuthProvider.ID))
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

	mfaEnabled, err := hasUserMFAEnabledIdentity(ctx, s.db, u.ID)
	if err != nil {
		return nil, err
	}
	if mfaEnabled {
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

	resolvedUser, err := s.findLDAPUser(conn, username)
	if err != nil {
		s.logger.Errorf("ldap login failed: user search failed, provider=%s username=%s err=%v", s.ProviderName, username, err)
		return nil, err
	}
	if resolvedUser == nil || resolvedUser.DN == "" {
		s.logger.Warnf("ldap login failed: user not found in ldap, provider=%s username=%s", s.ProviderName, username)
		return &passwordCheckResult{}, nil
	}
	userDN := resolvedUser.DN
	s.logger.Infof(
		"ldap login debug: user found, provider=%s username=%s resolved_username=%s user_dn=%s",
		s.ProviderName,
		username,
		resolvedUser.Username,
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
	normalizedPhone := s.normalizeLDAPUserPhone(resolvedUser.Attrs)

	ldapIdentity, err := s.db.UserIdentities.Query().
		Select(
			useridentities.FieldID,
			useridentities.FieldUserID,
		).
		Where(
			useridentities.ProviderIDEQ(s.AuthProvider.ID),
			useridentities.ProviderUserIDEQ(resolvedUser.ProviderUserID),
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
	if ldapIdentity != nil {
		localUserID = ldapIdentity.UserID
		s.logger.Infof(
			"ldap login debug: identity hit, provider=%s user_dn=%s local_user_id=%d",
			s.ProviderName,
			maskLDAPDN(userDN),
			localUserID,
		)
	} else {
		s.logger.Warnf(
			"ldap login debug: identity miss, start verified identifier resolve or provision, provider=%s username=%s resolved_username=%s user_dn=%s",
			s.ProviderName,
			username,
			resolvedUser.Username,
			maskLDAPDN(userDN),
		)
		localUserID, err = s.provisionLDAPUserOnFirstLogin(ctx, resolvedUser.ProviderUserID, resolvedUser.Username, resolvedUser.Attrs, normalizedPhone)
		if err != nil {
			s.logger.Errorf(
				"ldap login failed: auto provision error, provider=%s username=%s resolved_username=%s user_dn=%s err=%v",
				s.ProviderName,
				username,
				resolvedUser.Username,
				maskLDAPDN(userDN),
				err,
			)
			return nil, err
		}
		s.logger.Infof(
			"ldap login debug: identity resolve or provision success, provider=%s user_dn=%s local_user_id=%d",
			s.ProviderName,
			maskLDAPDN(userDN),
			localUserID,
		)
	}
	// 无论 identity 是已有、自动关联还是首次创建，都从同一入口同步最新的非空 LDAP 属性。
	s.syncLDAPUserAttrs(ctx, localUserID, resolvedUser.Attrs, normalizedPhone)

	userEntity, err := s.db.Users.Query().
		Select(
			users.FieldID,
			users.FieldUsername,
			users.FieldNickname,
		).
		Where(
			users.IDEQ(localUserID),
			users.UserStatusEQ(int(adminv1.User_ACTIVE.Number())),
			users.DeletedAtIsNil(),
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

	mfaEnabled, err := hasUserMFAEnabledIdentity(ctx, s.db, userEntity.ID)
	if err != nil {
		return nil, err
	}
	if mfaEnabled {
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

func (s *socialUsers) provisionLDAPUserOnFirstLogin(
	ctx context.Context,
	providerUserID string,
	ldapUsername string,
	attrs *ldapUserAttrs,
	phone *normalizedPhoneNumber,
) (int, error) {
	autoLinkEnabled := false
	if (attrs != nil && strings.TrimSpace(attrs.Email) != "") || phone != nil {
		var settingErr error
		autoLinkEnabled, settingErr = s.identityAutoLinkEnabled(ctx)
		if settingErr != nil {
			return 0, settingErr
		}
	}

	tx, err := s.db.Tx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var assertedEmail string
	if attrs != nil {
		assertedEmail = attrs.Email
	}
	var assertedPhone string
	if phone != nil {
		assertedPhone = phone.Identifier.StoredValue
	}
	linkedUserID, linked, err := s.linkExternalIdentityByVerifiedIdentifiers(
		ctx,
		tx,
		providerUserID,
		verifiedIdentityClaims{
			Email:               assertedEmail,
			EmailVerified:       assertedEmail != "",
			PhoneNumber:         assertedPhone,
			PhoneNumberVerified: assertedPhone != "",
		},
		autoLinkEnabled,
		nil,
	)
	if err != nil {
		return 0, err
	}
	if linked {
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit LDAP verified identifier binding: %w", err)
		}
		return linkedUserID, nil
	}

	baseUsername := buildLDAPLocalUsernameBase(s.ProviderName, ldapUsername)
	localUsername, err := findAvailableUsername(ctx, tx, baseUsername)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	userCreate := tx.Users.Create().
		SetUsername(localUsername).
		SetUserStatus(int(adminv1.User_ACTIVE.Number()))

	// 昵称优先使用 LDAP displayName，其次回退到 username 属性值。
	nickname := ldapUsername
	if attrs != nil && attrs.DisplayName != "" {
		nickname = attrs.DisplayName
	}
	userCreate.SetNickname(nickname)

	var emailIdentifier canonicalIdentifier
	// 写入邮箱（加密 + hash + verified 标记）。LDAP 用户已经完成
	// directory bind，因此该 Provider 返回的邮箱属于可信断言。
	if attrs != nil && attrs.Email != "" {
		var identifierErr error
		emailIdentifier, identifierErr = canonicalizeEmailIdentifier(attrs.Email)
		if identifierErr != nil {
			s.logger.Warnf("ignore invalid LDAP email: provider=%s err=%v", s.ProviderName, identifierErr)
		} else {
			emailEnc, encErr := crypto.EncryptAES(s.aesKey, []byte(emailIdentifier.StoredValue))
			if encErr != nil {
				_ = tx.Rollback()
				return 0, fmt.Errorf("encrypt ldap email: %w", encErr)
			}
			userCreate.SetEmailEncrypted(emailEnc)
			userCreate.SetEmailHash(emailIdentifier.Hash)
			userCreate.SetEmailVerified(true)
		}
	}
	if phone != nil {
		phoneEnc, encErr := s.encryptPhoneNumber(phone.Proto)
		if encErr != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("encrypt ldap phone number: %w", encErr)
		}
		userCreate.SetPhoneNumberEncrypted(phoneEnc)
		userCreate.SetPhoneNumberHash(phone.Identifier.Hash)
		userCreate.SetPhoneNumberVerified(true)
	}

	newUser, err := userCreate.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		if emailIdentifier.Hash != "" && lion.IsConstraintError(err) {
			if _, queryErr := s.db.Users.Query().
				Where(users.EmailHashEQ(emailIdentifier.Hash)).
				OnlyID(ctx); queryErr == nil {
				return 0, errExternalEmailAlreadyExists
			}
		}
		if phone != nil && lion.IsConstraintError(err) {
			if _, queryErr := s.db.Users.Query().
				Where(users.PhoneNumberHashEQ(phone.Identifier.Hash)).
				OnlyID(ctx); queryErr == nil {
				return 0, errExternalPhoneAlreadyExists
			}
		}
		return 0, err
	}

	_, err = tx.UserIdentities.Create().
		SetUserID(newUser.ID).
		SetProviderID(s.AuthProvider.ID).
		SetProviderUserID(providerUserID).
		Save(ctx)
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return 0, fmt.Errorf("create LDAP identity: %w (rollback: %v)", err, rollbackErr)
		}
		if lion.IsConstraintError(err) {
			// Another first-login request may have created the authoritative
			// identity after our initial miss. The failed transaction is already
			// rolled back; reread from the root client and converge on that user.
			existing, queryErr := s.db.UserIdentities.Query().
				Select(useridentities.FieldUserID).
				Where(
					useridentities.ProviderIDEQ(s.AuthProvider.ID),
					useridentities.ProviderUserIDEQ(providerUserID),
				).
				Only(ctx)
			if queryErr == nil {
				return existing.UserID, nil
			}
			if !lion.IsNotFound(queryErr) {
				return 0, fmt.Errorf("reread LDAP identity after constraint failure: %w", queryErr)
			}
		}
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newUser.ID, nil
}

// syncLDAPUserAttrs 在已有用户二次登录时，用最新 LDAP 属性刷新本地用户表。
// 仅当 LDAP 侧返回了非空值时才覆盖对应字段，避免用空值清掉已有数据。
func (s *socialUsers) syncLDAPUserAttrs(ctx context.Context, userID int, attrs *ldapUserAttrs, phone *normalizedPhoneNumber) {
	if attrs == nil {
		return
	}

	userUpdate := s.db.Users.Update().Where(users.IDEQ(userID), users.UserStatusEQ(int(adminv1.User_ACTIVE.Number())), users.DeletedAtIsNil())

	updated := false
	if attrs.DisplayName != "" {
		userUpdate.SetNickname(attrs.DisplayName)
		updated = true
	}
	if attrs.Email != "" {
		identifier, err := canonicalizeEmailIdentifier(attrs.Email)
		if err != nil {
			s.logger.Warnf("ldap sync attrs: ignore invalid email, provider=%s user_id=%d err=%v", s.ProviderName, userID, err)
		} else {
			emailEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(identifier.StoredValue))
			if encryptErr != nil {
				s.logger.Warnf("ldap sync attrs: encrypt email failed, provider=%s user_id=%d err=%v", s.ProviderName, userID, encryptErr)
			} else {
				userUpdate.SetEmailEncrypted(emailEnc)
				userUpdate.SetEmailHash(identifier.Hash)
				userUpdate.SetEmailVerified(true)
				updated = true
			}
		}
	}

	if updated {
		if n, err := userUpdate.Save(ctx); err != nil {
			s.logger.Warnf("ldap sync attrs: update user failed, provider=%s user_id=%d affected=%d err=%v", s.ProviderName, userID, n, err)
		} else {
			s.logger.Infof("ldap sync attrs: update user success, provider=%s user_id=%d affected=%d", s.ProviderName, userID, n)
		}
	}

	if phone != nil {
		s.syncLDAPUserPhone(ctx, userID, phone)
	}
}

func (s *socialUsers) syncLDAPUserPhone(ctx context.Context, userID int, phone *normalizedPhoneNumber) {
	phoneEnc, err := s.encryptPhoneNumber(phone.Proto)
	if err != nil {
		s.logger.Warnf("ldap phone sync failed: encrypt phone number, provider=%s user_id=%d err=%v", s.ProviderName, userID, err)
		return
	}

	n, err := s.db.Users.Update().
		Where(
			users.IDEQ(userID),
			users.UserStatusEQ(int(adminv1.User_ACTIVE.Number())),
			users.DeletedAtIsNil(),
		).
		SetPhoneNumberEncrypted(phoneEnc).
		SetPhoneNumberHash(phone.Identifier.Hash).
		SetPhoneNumberVerified(true).
		Save(ctx)
	if err != nil {
		if lion.IsConstraintError(err) {
			s.logger.Warnf("ldap phone sync skipped: phone number conflict, provider=%s user_id=%d", s.ProviderName, userID)
			return
		}
		s.logger.Warnf("ldap phone sync failed: update user, provider=%s user_id=%d affected=%d err=%v", s.ProviderName, userID, n, err)
		return
	}
	s.logger.Infof("ldap phone sync success: provider=%s user_id=%d affected=%d", s.ProviderName, userID, n)
}

func (s *socialUsers) encryptPhoneNumber(phone *adminv1.PhoneNumber) ([]byte, error) {
	raw, err := proto.Marshal(phone)
	if err != nil {
		return nil, fmt.Errorf("marshal phone number: %w", err)
	}
	return crypto.EncryptAES(s.aesKey, raw)
}

func (s *socialUsers) normalizeLDAPUserPhone(attrs *ldapUserAttrs) *normalizedPhoneNumber {
	if attrs == nil || strings.TrimSpace(attrs.PhoneNumber) == "" {
		return nil
	}
	phone, err := normalizeExternalPhoneNumber(attrs.PhoneNumber, s.ldapCfg.PhoneNumberDefaultRegion)
	if err != nil {
		s.logger.Warnf("ldap phone ignored: invalid phone number, provider=%s", s.ProviderName)
		return nil
	}
	return &phone
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
	return s.issueAccessTokenForUserID(ctx, u.ID)
}

func (s *socialUsers) issueAccessTokenForUserID(ctx context.Context, userID int) (string, bool, error) {
	profile, err := loadAccessTokenUserProfile(ctx, s.db, s.aesKey, userID)
	if err != nil {
		return "", false, err
	}
	now := time.Now()
	roleIDs, err := effectiveRoleIDsForUserAt(ctx, s.db, userID, now)
	if err != nil {
		return "", false, err
	}
	roleCodes, err := roleCodesForIDs(ctx, s.db, roleIDs)
	if err != nil {
		return "", false, err
	}
	groupCodes, err := effectiveGroupCodesForUserAt(ctx, s.db, userID, now)
	if err != nil {
		return "", false, err
	}
	input := accessTokenInputFromProfile(profile, s.issuanceContext, roleCodes, groupCodes)
	accessToken, err := newAccessTokenIssuer().issueRSA(input, s.privateKey, s.kid)
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

// ldapUserAttrs 携带从 LDAP 搜索结果中提取的用户属性。
type ldapUserAttrs struct {
	Email       string
	DisplayName string
	PhoneNumber string
}

type ldapResolvedUser struct {
	DN             string
	Username       string
	ProviderUserID string
	Attrs          *ldapUserAttrs
}

func (s *socialUsers) findLDAPUser(conn *ldap.Conn, username string) (*ldapResolvedUser, error) {
	searchBase := strings.TrimSpace(s.ldapCfg.UserSearchBase)
	if searchBase == "" {
		s.logger.Errorf("ldap search failed: empty user_search_base, provider=%s username=%s", s.ProviderName, username)
		return nil, fmt.Errorf("ldap user_search_base is required")
	}

	usernameAttribute := strings.TrimSpace(s.ldapCfg.UsernameAttribute)
	if usernameAttribute == "" {
		usernameAttribute = "uid"
	}

	userIDAttribute, err := normalizeLDAPUserIDAttributeName(effectiveLDAPUserIDAttribute(s.ldapCfg))
	if err != nil {
		return nil, err
	}

	// 构建请求属性列表：始终包含 username 属性，按配置追加主体和资料属性。
	attributes := make([]string, 0, 5)
	appendAttribute := func(attribute string) {
		attribute = strings.TrimSpace(attribute)
		if attribute == "" || strings.EqualFold(attribute, legacyLDAPUserIDAttribute) {
			return
		}
		for _, existing := range attributes {
			if strings.EqualFold(existing, attribute) {
				return
			}
		}
		attributes = append(attributes, attribute)
	}
	appendAttribute(usernameAttribute)
	appendAttribute(userIDAttribute)
	emailAttribute := strings.TrimSpace(s.ldapCfg.EmailAttribute)
	displayNameAttribute := strings.TrimSpace(s.ldapCfg.DisplayNameAttribute)
	phoneNumberAttribute, err := normalizeLDAPPhoneNumberAttributeName(s.ldapCfg.PhoneNumberAttribute)
	if err != nil {
		return nil, err
	}
	appendAttribute(emailAttribute)
	appendAttribute(displayNameAttribute)
	appendAttribute(phoneNumberAttribute)

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
		"ldap search debug: provider=%s username=%s search_base=%s username_attr=%s user_id_attr=%s",
		s.ProviderName,
		username,
		maskLDAPDN(searchBase),
		usernameAttribute,
		userIDAttribute,
	)

	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		0,
		false,
		filter,
		attributes,
		nil,
	)
	searchResp, err := conn.Search(searchReq)
	if err != nil {
		s.logger.Errorf("ldap search failed: provider=%s username=%s err=%v", s.ProviderName, username, err)
		return nil, err
	}
	s.logger.Infof(
		"ldap search debug: provider=%s username=%s entry_count=%d",
		s.ProviderName,
		username,
		len(searchResp.Entries),
	)
	if len(searchResp.Entries) == 0 {
		return nil, nil
	}
	if len(searchResp.Entries) > 1 {
		s.logger.Warnf("ldap search failed: multiple entries, provider=%s username=%s entry_count=%d", s.ProviderName, username, len(searchResp.Entries))
		return nil, fmt.Errorf("ldap user search returned multiple entries")
	}

	entry := searchResp.Entries[0]
	resolvedUsername := strings.TrimSpace(entry.GetEqualFoldAttributeValue(usernameAttribute))
	if resolvedUsername == "" {
		resolvedUsername = username
	}
	providerUserID, err := resolveLDAPProviderUserID(entry, userIDAttribute)
	if err != nil {
		return nil, err
	}

	attrs := &ldapUserAttrs{}
	if emailAttribute != "" {
		attrs.Email = strings.TrimSpace(entry.GetEqualFoldAttributeValue(emailAttribute))
	}
	if displayNameAttribute != "" {
		attrs.DisplayName = strings.TrimSpace(entry.GetEqualFoldAttributeValue(displayNameAttribute))
	}
	if phoneNumberAttribute != "" {
		phoneNumber, phoneErr := singleLDAPAttributeValue(entry, phoneNumberAttribute)
		if phoneErr != nil {
			s.logger.Warnf("ldap phone ignored: attribute must be single-valued, provider=%s", s.ProviderName)
		} else {
			attrs.PhoneNumber = phoneNumber
		}
	}

	return &ldapResolvedUser{
		DN:             entry.DN,
		Username:       resolvedUsername,
		ProviderUserID: providerUserID,
		Attrs:          attrs,
	}, nil
}

func singleLDAPAttributeValue(entry *ldap.Entry, attribute string) (string, error) {
	if entry == nil || strings.TrimSpace(attribute) == "" {
		return "", nil
	}

	var result string
	for _, value := range entry.GetEqualFoldAttributeValues(attribute) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if result != "" {
			return "", fmt.Errorf("ldap attribute must contain at most one non-empty value")
		}
		result = trimmed
	}
	return result, nil
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

func (s *socialUsers) upsertUserOIDC(ctx context.Context, oauth2Token *oauth2.Token, profile externalUserClaims) (int, error) {
	existIdentity, err := s.db.UserIdentities.Query().
		Where(
			useridentities.ProviderID(s.AuthProvider.ID),
			useridentities.ProviderUserIDEQ(profile.ProviderSubject),
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
		autoLinkEnabled := false
		if (profile.EmailVerified && strings.TrimSpace(profile.Email) != "") ||
			(profile.PhoneNumberVerified && strings.TrimSpace(profile.PhoneNumber) != "") {
			autoLinkEnabled, err = s.identityAutoLinkEnabled(ctx)
			if err != nil {
				return 0, err
			}
		}

		tx, err := s.db.Tx(ctx)
		if err != nil {
			s.logger.Errorf("create external user: provider=%s err=%v", s.ProviderName, err)
			return 0, fmt.Errorf("create user failed")
		}
		defer func() { _ = tx.Rollback() }()

		linkedUserID, linked, err := s.linkExternalIdentityByVerifiedIdentifiers(
			ctx,
			tx,
			profile.ProviderSubject,
			verifiedIdentityClaims{
				Email:               profile.Email,
				EmailVerified:       profile.EmailVerified,
				PhoneNumber:         profile.PhoneNumber,
				PhoneNumberVerified: profile.PhoneNumberVerified,
			},
			autoLinkEnabled,
			oauth2Token,
		)
		if err != nil {
			return 0, err
		}
		if linked {
			if err := tx.Commit(); err != nil {
				return 0, fmt.Errorf("commit verified identifier identity binding: %w", err)
			}
			return linkedUserID, nil
		}

		usernameSource := profile.Username
		if strings.TrimSpace(usernameSource) == "" {
			usernameSource = profile.ProviderSubject
		}
		username, err := findAvailableUsername(ctx, tx, buildLDAPLocalUsernameBase(s.ProviderName, usernameSource))
		if err != nil {
			s.logger.Errorf("allocate external username: provider=%s err=%v", s.ProviderName, err)
			return 0, fmt.Errorf("create user failed")
		}

		userCreate := tx.Users.Create().SetUsername(username)
		var emailIdentifier canonicalIdentifier
		if profile.Email != "" {
			var identifierErr error
			emailIdentifier, identifierErr = canonicalizeEmailIdentifier(profile.Email)
			if identifierErr != nil {
				s.logger.Warnf("ignore invalid external email: provider=%s err=%v", s.ProviderName, identifierErr)
			} else {
				emailEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(emailIdentifier.StoredValue))
				if encryptErr != nil {
					return 0, fmt.Errorf("encrypt external user email: %w", encryptErr)
				}
				userCreate.SetEmailEncrypted(emailEnc).
					SetEmailHash(emailIdentifier.Hash).
					SetEmailVerified(profile.EmailVerified)
			}
		}

		newUser, err := userCreate.Save(ctx)
		if err != nil {
			_ = tx.Rollback()
			if profile.EmailVerified && emailIdentifier.Hash != "" && lion.IsConstraintError(err) {
				if _, queryErr := s.db.Users.Query().
					Where(users.EmailHashEQ(emailIdentifier.Hash)).
					OnlyID(ctx); queryErr == nil {
					return 0, errExternalEmailAlreadyExists
				}
			}

			s.logger.Errorf("create user: %v, to save err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		identityCreate := tx.UserIdentities.Create().
			SetUserID(newUser.ID).
			SetProviderID(s.AuthProvider.ID).
			SetProviderUserID(profile.ProviderSubject)
		if oauth2Token.AccessToken != "" {
			accessTokenEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(oauth2Token.AccessToken))
			if encryptErr != nil {
				return 0, fmt.Errorf("encrypt external access token: %w", encryptErr)
			}
			identityCreate.SetAccessTokenEncrypted(accessTokenEnc)
		}
		if oauth2Token.RefreshToken != "" {
			refreshTokenEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(oauth2Token.RefreshToken))
			if encryptErr != nil {
				return 0, fmt.Errorf("encrypt external refresh token: %w", encryptErr)
			}
			identityCreate.SetRefreshTokenEncrypted(refreshTokenEnc)
		}
		if !oauth2Token.Expiry.IsZero() {
			identityCreate.SetTokenExpiresAt(oauth2Token.Expiry)
		}

		_, err = identityCreate.Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit external user creation: %w", err)
		}
		existUserID = newUser.ID
	} else {
		identityUpdate := s.db.UserIdentities.Update().Where(useridentities.IDEQ(existIdentity.ID))
		hasUpdate := false
		if oauth2Token.AccessToken != "" {
			accessTokenEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(oauth2Token.AccessToken))
			if encryptErr != nil {
				return 0, fmt.Errorf("encrypt external access token: %w", encryptErr)
			}
			identityUpdate.SetAccessTokenEncrypted(accessTokenEnc)
			hasUpdate = true
		}
		if oauth2Token.RefreshToken != "" {
			refreshTokenEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(oauth2Token.RefreshToken))
			if encryptErr != nil {
				return 0, fmt.Errorf("encrypt external refresh token: %w", encryptErr)
			}
			identityUpdate.SetRefreshTokenEncrypted(refreshTokenEnc)
			hasUpdate = true
		}
		if !oauth2Token.Expiry.IsZero() {
			identityUpdate.SetTokenExpiresAt(oauth2Token.Expiry)
			hasUpdate = true
		}
		if hasUpdate {
			if _, err := identityUpdate.Save(ctx); err != nil {
				return 0, fmt.Errorf("update external identity token: %w", err)
			}
		}

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
		if email, verified := s.githubPrimaryEmail(ctx, oauth2Token.AccessToken); email != "" {
			userinfo["email"] = email
			userinfo["email_verified"] = verified
		}
	}

	return userinfo, nil
}

func (s *socialUsers) githubPrimaryEmail(ctx context.Context, accessToken string) (string, bool) {
	apiURL := strings.TrimSuffix(s.oauthCfg.ApiURL, "/")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/user/emails", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err = json.Unmarshal(body, &emails); err != nil {
		return "", false
	}

	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			return e.Email, true
		}
	}
	for _, e := range emails {
		if e.Verified && e.Email != "" {
			return e.Email, true
		}
	}
	for _, e := range emails {
		if e.Primary && e.Email != "" {
			return e.Email, false
		}
	}
	if len(emails) > 0 {
		return emails[0].Email, emails[0].Verified
	}
	return "", false
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
		Select(
			useridentities.FieldID,
			useridentities.FieldUserID,
			useridentities.FieldProviderUnionID,
		).
		Only(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return 0, err
	}

	var existUserID int
	if existIdentity != nil {
		existUserID = existIdentity.UserID

		unionID, shouldPersist, conflict := reconcileWechatUnionID(existIdentity.ProviderUnionID, resp.Unionid)
		if conflict {
			// UnionID 不参与当前登录匹配。发生冲突时保留已存值，避免在尚未建模
			// 微信开放平台账号信任域之前错误覆盖跨应用身份标识。
			s.logger.Warnf(
				"wechat unionid mismatch: provider=%s identity_id=%d; keeping stored value",
				s.ProviderName,
				existIdentity.ID,
			)
		}
		if shouldPersist {
			if _, updateErr := s.db.UserIdentities.UpdateOneID(existIdentity.ID).
				SetProviderUnionID(unionID).
				Save(ctx); updateErr != nil {
				return 0, fmt.Errorf("backfill wechat unionid: %w", updateErr)
			}
		}
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

		newUser, err := tx.Users.Create().
			SetUsername(username).
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

		identityCreate := tx.UserIdentities.Create().
			SetUserID(newUser.ID).
			SetProviderID(s.AuthProvider.ID).
			SetProviderUserID(resp.Openid).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc)
		if unionID := strings.TrimSpace(resp.Unionid); unionID != "" {
			identityCreate.SetProviderUnionID(unionID)
		}
		_, err = identityCreate.
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

// reconcileWechatUnionID 决定微信登录返回的 UnionID 是否需要持久化。
// 空值不会清除历史数据；已存值与新值冲突时保留历史数据并交由上层记录告警。
func reconcileWechatUnionID(stored, incoming string) (value string, shouldPersist, conflict bool) {
	stored = strings.TrimSpace(stored)
	incoming = strings.TrimSpace(incoming)

	switch {
	case incoming == "":
		return stored, false, false
	case stored == "":
		return incoming, true, false
	case stored == incoming:
		return stored, false, false
	default:
		return stored, false, true
	}
}
