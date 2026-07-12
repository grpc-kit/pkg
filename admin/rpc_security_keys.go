package admin

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateCredential 生成签名密钥
func (a *KnownAdminAPI) CreateCredential(ctx context.Context, req *adminv1.CreateCredentialRequest) (*adminv1.Credential, error) {
	result := &adminv1.Credential{}

	// 仅允许存在一条记录，如已存在多次创建返回已存在内容

	/*
		tx, err := a.config.db.Tx(ctx)
		if err != nil {
			return nil, err
		}

		key, err := tx.Credentials.Query().Select(credentials.FieldPublicKey).Only(ctx)
		if err != nil && !lion.IsNotFound(err) {
			return nil, err
		}

		// 不存在记录则新建
		if lion.IsNotFound(err) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}

			privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
			publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if err != nil {
				return nil, err
			}

			privateKeyEnc, err := crypto.EncryptAES(a.config.aesKey, privateKeyBytes)
			if err != nil {
				return nil, err
			}

			appid := uuid.New().String()
			if req.Credential.Appid != "" {
				appid = req.Credential.Appid
			}

			tx.Credentials.Create().
				SetName(req.Credential.Name).
				SetType(int(req.Credential.Type)).
				SetAppid(appid).
				SetUsage(req.Credential.Usage).
				SetPublicKey(crypto.Base64Encode(publicKeyBytes)).
				SetPrivateKeyEncrypted(privateKeyEnc).SaveX(ctx)

			result.PublicKey = crypto.Base64Encode(publicKeyBytes)
		} else {
			result.PublicKey = key.PublicKey
		}

		_ = tx.Commit()
	*/

	return result, nil
}

// GetOAuth2Discovery 获取内置 OpenID 配置
func (a *KnownAdminAPI) GetOAuth2Discovery(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Discovery, error) {
	result := &adminv1.OAuth2Discovery{}

	issuer := "http://127.0.0.1:8080/builtin/admin/api/v1/oauth2"

	if a.config.issuer != "" {
		issuer = a.config.issuer
	}

	result.Issuer = issuer
	result.AuthorizationEndpoint = issuer + "/authorize"
	result.TokenEndpoint = issuer + "/token"
	result.JwksUri = issuer + "/jwks"

	result.ResponseTypesSupported = []string{"none"}
	result.SubjectTypesSupported = []string{"public"}
	result.IdTokenSigningAlgValuesSupported = []string{"RS256"}

	return result, nil
}

// GetOAuth2JSONWebKeys 获取内置 OpenID 公钥
func (a *KnownAdminAPI) GetOAuth2JSONWebKeys(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2JSONWebKeys, error) {
	result := &adminv1.OAuth2JSONWebKeys{
		Keys: make([]*adminv1.OAuth2JSONWebKeys_Key, 0),
	}

	sk, err := a.config.db.Credentials.Query().
		Select(
			credentials.FieldKeyID,
			credentials.FieldPublicKey,
		).
		Where(
			credentials.CredentialTypeEQ(int(adminv1.Credential_KEY_PAIR.Number())),
			credentials.CredentialAlgorithmEQ(int(adminv1.Credential_RSA.Number())),
			credentials.CredentialUsageEQ(int(adminv1.Credential_JWKS.Number())),
			credentials.CredentialVisibilityEQ(int(adminv1.Visibility_VISIBILITY_RESTRICTED.Number())),
			credentials.CredentialStatusEQ(int(adminv1.Credential_ACTIVE.Number())),
			credentials.CredentialSourceEQ(int(adminv1.Credential_SYSTEM.Number())),
		).
		Order(credentials.ByID()).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	pubInterface, err := x509.ParsePKIXPublicKey(sk.PublicKey)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	// 将模数 N 和指数 E 转换为 Base64URL 编码
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	tmp := &adminv1.OAuth2JSONWebKeys_Key{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		E:   e,
		N:   n,
		Kid: sk.KeyID,
	}

	result.Keys = append(result.Keys, tmp)

	return result, nil
}

// GetOAuth2Userinfo 获取内置 OpenID 用户信息
// 对应 OIDC userinfo endpoint，返回 OIDC Standard Claims 规范定义的用户信息
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (a *KnownAdminAPI) GetOAuth2Userinfo(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Userinfo, error) {
	result := &adminv1.OAuth2Userinfo{}

	tmp := rpc.GetIDTokenFromContext(ctx)
	a.logger.Infof("get id token type: %v", reflect.TypeOf(tmp))
	idToken, ok := tmp.(auth.IDTokenClaims)
	if !ok {
		return result, errs.PermissionDenied(ctx)
	}

	// 从 JWT 中提取基础 claim（这些字段在签发 token 时已确定）
	result.Sub = idToken.Subject
	result.UserId = idToken.GetMustUserID()
	result.PreferredUsername = idToken.Username
	result.Email = idToken.Email
	result.EmailVerified = idToken.EmailVerified

	// 从数据库查询用户实体，补充完整 OIDC Standard Claims
	userID := result.UserId
	if userID <= 0 {
		// 缺少 user_id 时仅返回 JWT 中的基础 claim
		return result, nil
	}

	user, err := a.config.db.Users.Query().
		Select(
			users.FieldID,
			users.FieldNickname,
			users.FieldProfile,
			users.FieldPicture,
			users.FieldWebsite,
			users.FieldGender,
			users.FieldBirthdate,
			users.FieldTimezone,
			users.FieldLocale,
			users.FieldEmailVerified,
			users.FieldPhoneNumberVerified,
			users.FieldRealnameEncrypted,
			users.FieldEmailEncrypted,
			users.FieldPhoneNumberEncrypted,
			users.FieldUpdatedAt,
		).
		Where(users.IDEQ(int(userID))).
		Only(ctx)
	if err != nil {
		// 用户查询失败时降级返回 JWT 中的基础 claim，避免 userinfo endpoint 整体不可用
		if lion.IsNotFound(err) {
			a.logger.Infof("oauth2 userinfo: user %d not found, returning jwt claims only", userID)
			return result, nil
		}
		a.logger.Infof("oauth2 userinfo: query user %d failed: %v, returning jwt claims only", userID, err)
		return result, nil
	}

	result.Nickname = user.Nickname
	result.Profile = user.Profile
	result.Picture = user.Picture
	result.Website = user.Website
	result.Zoneinfo = user.Timezone
	result.Locale = user.Locale
	result.PhoneNumberVerified = user.PhoneNumberVerified

	// email_verified 以数据库值为准（JWT 中可能过期）
	if user.EmailVerified {
		result.EmailVerified = true
	}

	// realname 解密映射到 OIDC name claim；若 realname 为空则回退到 nickname
	realname, err := a.decryptStringField(ctx, users.FieldRealnameEncrypted, user.RealnameEncrypted)
	if err != nil {
		return nil, err
	}
	if realname != "" {
		result.Name = realname
	} else {
		result.Name = user.Nickname
	}

	// email 解密（JWT 中 email 可能为空或过期，以数据库为准）
	email, err := a.decryptStringField(ctx, users.FieldEmailEncrypted, user.EmailEncrypted)
	if err != nil {
		return nil, err
	}
	if email != "" {
		result.Email = email
	}

	// phone_number 解密并格式化为 E.164 字符串
	phoneNumber, err := a.decryptPhoneNumberField(ctx, user.PhoneNumberEncrypted)
	if err != nil {
		return nil, err
	}
	if phoneNumber != nil && phoneNumber.GetCountryCode() != "" && phoneNumber.GetNationalNumber() != "" {
		result.PhoneNumber = fmt.Sprintf("+%s%s", phoneNumber.GetCountryCode(), phoneNumber.GetNationalNumber())
	}

	// gender enum → OIDC string
	result.Gender = genderToOIDCString(adminv1.User_Gender(user.Gender))

	// birthdate Timestamp → ISO 8601 "YYYY-MM-DD" 字符串
	if user.Birthdate != nil {
		result.Birthdate = user.Birthdate.Format("2006-01-02")
	}

	// updated_at → Unix 时间戳（秒）
	result.UpdatedAt = user.UpdatedAt.Unix()

	return result, nil
}

// genderToOIDCString 将 User.Gender enum 映射为 OIDC Standard Claims 规范的 gender 字符串值
// OIDC 规范未强制枚举，常见值为 "male"/"female"/"other"；PRIVATE 和 UNSPECIFIED 返回空字符串（不返回该 claim）
func genderToOIDCString(g adminv1.User_Gender) string {
	switch g {
	case adminv1.User_MALE:
		return "male"
	case adminv1.User_FEMALE:
		return "female"
	case adminv1.User_OTHER:
		return "other"
	default:
		// GENDER_UNSPECIFIED / PRIVATE 不返回
		return ""
	}
}
