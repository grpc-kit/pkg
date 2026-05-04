package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/userroles"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/pquerna/otp/totp"
	"google.golang.org/protobuf/types/known/emptypb"
)

// VerifyAuthMFA 登录时的 MFA 二步验证
func (a *KnownAdminAPI) VerifyAuthMFA(ctx context.Context, req *adminv1.VerifyAuthMFARequest) (*adminv1.AuthToken, error) {
	if req.ChallengeId == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("challenge_id is required")
	}
	if req.TotpCode == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("totp_code is required")
	}

	challenge, ok := a.mfaChallenges.Get(req.ChallengeId)
	if !ok {
		return nil, errs.FailedPrecondition(ctx).WithMessage("challenge expired or not found")
	}
	if challenge.ChallengeType != mfaChallengeTypeLoginVerify {
		return nil, errs.FailedPrecondition(ctx).WithMessage("invalid challenge type")
	}

	attempts := a.mfaChallenges.IncrAttempts(req.ChallengeId)
	if attempts > mfaMaxAttempts {
		a.mfaChallenges.Delete(req.ChallengeId)
		return nil, errs.FailedPrecondition(ctx).WithMessage("too many MFA attempts, please login again")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}

	enforce, localProviderID, pErr := a.getLocalMFAPolicy(ctx, db)
	if pErr != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query local MFA policy")
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := tx.UserIdentities.Query().
		Select(
			useridentities.FieldID,
			useridentities.FieldProviderID,
			useridentities.FieldMfaSecretEncrypted,
			useridentities.FieldMfaRecoveryCodesEncrypted,
			useridentities.FieldMfaEnabled,
		).
		Where(
			useridentities.UserIDEQ(challenge.UserID),
			useridentities.MfaEnabledEQ(true),
		)
	if enforce && localProviderID > 0 {
		query = query.Where(useridentities.ProviderIDEQ(localProviderID))
	}

	identity, err := query.First(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query user identity")
	}
	if !identity.MfaEnabled {
		return nil, errs.FailedPrecondition(ctx).WithMessage("MFA is not enabled for this user")
	}

	secretBytes, err := crypto.DecryptAES(a.config.aesKey, identity.MfaSecretEncrypted)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to decrypt MFA secret")
	}

	recoveryCodeConsumed := false
	if !totp.Validate(req.TotpCode, string(secretBytes)) {
		recoveryCodesEncryptedAfterConsume, consumed, consumeErr := consumeRecoveryCodeEncrypted(
			a.config.aesKey,
			identity.MfaRecoveryCodesEncrypted,
			req.TotpCode,
			time.Now(),
		)
		if consumeErr != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to verify recovery code")
		}
		if !consumed {
			return nil, errs.Unauthenticated(ctx).WithMessage("invalid TOTP code or recovery code")
		}
		recoveryCodeConsumed = true

		affected, saveErr := tx.UserIdentities.Update().
			Where(
				useridentities.UserIDEQ(challenge.UserID),
				useridentities.ProviderIDEQ(identity.ProviderID),
				useridentities.MfaEnabledEQ(true),
				useridentities.MfaRecoveryCodesEncryptedEQ(identity.MfaRecoveryCodesEncrypted),
			).
			SetMfaRecoveryCodesEncrypted(recoveryCodesEncryptedAfterConsume).
			Save(ctx)
		if saveErr != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to consume recovery code")
		}
		if affected == 0 {
			return nil, errs.FailedPrecondition(ctx).WithMessage("recovery code already used or MFA state changed")
		}
	}

	accessToken, err := a.issueTokenForUser(ctx, db, challenge.UserID)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to issue access token")
	}
	if err := tx.Commit(); err != nil {
		if recoveryCodeConsumed {
			return nil, errs.Internal(ctx).WithMessage("failed to commit recovery code consumption")
		}
		return nil, errs.Internal(ctx).WithMessage("failed to finalize MFA verification")
	}
	a.mfaChallenges.Delete(req.ChallengeId)

	return &adminv1.AuthToken{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   24 * 60 * 60,
	}, nil
}

// SetupUserMFA 初始化 MFA 设置（生成密钥 + 二维码 URI）
func (a *KnownAdminAPI) SetupUserMFA(ctx context.Context, req *adminv1.SetupUserMFARequest) (*adminv1.SetupUserMFAResponse, error) {
	if req.UserId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("user_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}

	u, err := db.Users.Query().
		Select(users.FieldID, users.FieldUsername).
		Where(users.IDEQ(int(req.UserId))).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("user not found")
		}
		return nil, errs.Internal(ctx).WithMessage("failed to query user")
	}

	_, localProviderID, err := a.getLocalMFAPolicy(ctx, db)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query local MFA policy")
	}
	if localProviderID == 0 {
		return nil, errs.FailedPrecondition(ctx).WithMessage("local auth provider not found")
	}

	if err := a.ensureLocalIdentity(ctx, db, u.ID, u.Username, localProviderID); err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to ensure local identity")
	}

	existingIdentity, err := db.UserIdentities.Query().
		Select(useridentities.FieldMfaEnabled).
		Where(
			useridentities.UserIDEQ(u.ID),
			useridentities.ProviderIDEQ(localProviderID),
		).
		First(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return nil, errs.Internal(ctx).WithMessage("failed to query user identity")
	}
	if existingIdentity != nil && existingIdentity.MfaEnabled {
		return nil, errs.FailedPrecondition(ctx).WithMessage("MFA is already enabled for this user, disable it first")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "KnownAdmin",
		AccountName: u.Username,
	})
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to generate TOTP key")
	}

	challenge, err := a.mfaChallenges.Create(mfaChallengeTypeAdminSetup, u.ID, u.Username)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to create setup challenge")
	}
	challenge.TempSecret = key.Secret()

	return &adminv1.SetupUserMFAResponse{
		Secret:      key.Secret(),
		QrUri:       key.URL(),
		ChallengeId: challenge.ChallengeID,
	}, nil
}

// ConfirmUserMFA 确认开启 MFA
func (a *KnownAdminAPI) ConfirmUserMFA(ctx context.Context, req *adminv1.ConfirmUserMFARequest) (*adminv1.ConfirmUserMFAResponse, error) {
	if req.ChallengeId == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("challenge_id is required")
	}
	if req.TotpCode == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("totp_code is required")
	}

	challenge, ok := a.mfaChallenges.Get(req.ChallengeId)
	if !ok {
		return nil, errs.FailedPrecondition(ctx).WithMessage("challenge expired or not found")
	}
	if challenge.ChallengeType != mfaChallengeTypeAdminSetup {
		return nil, errs.FailedPrecondition(ctx).WithMessage("invalid challenge type")
	}
	if challenge.TempSecret == "" {
		return nil, errs.FailedPrecondition(ctx).WithMessage("no temporary secret in challenge")
	}

	if !totp.Validate(req.TotpCode, challenge.TempSecret) {
		attempts := a.mfaChallenges.IncrAttempts(req.ChallengeId)
		if attempts > mfaMaxAttempts {
			a.mfaChallenges.Delete(req.ChallengeId)
			return nil, errs.FailedPrecondition(ctx).WithMessage("too many attempts, please restart MFA setup")
		}
		return nil, errs.Unauthenticated(ctx).WithMessage("invalid TOTP code")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}

	secretEnc, err := crypto.EncryptAES(a.config.aesKey, []byte(challenge.TempSecret))
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to encrypt MFA secret")
	}
	recoveryCodes, err := generateRecoveryCodes(8)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to generate recovery codes")
	}
	recoveryCodesEnc, err := encryptRecoveryCodes(a.config.aesKey, recoveryCodes)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to encrypt recovery codes")
	}

	_, localProviderID, pErr := a.getLocalMFAPolicy(ctx, db)
	if pErr != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query local MFA policy")
	}
	if localProviderID == 0 {
		return nil, errs.FailedPrecondition(ctx).WithMessage("local auth provider not found")
	}

	if err := a.ensureLocalIdentity(ctx, db, challenge.UserID, challenge.Username, localProviderID); err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to ensure local identity")
	}

	_, err = db.UserIdentities.Update().
		Where(
			useridentities.UserIDEQ(challenge.UserID),
			useridentities.ProviderIDEQ(localProviderID),
		).
		SetMfaEnabled(true).
		SetMfaSecretEncrypted(secretEnc).
		SetMfaRecoveryCodesEncrypted(recoveryCodesEnc).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to enable MFA")
	}

	a.mfaChallenges.Delete(req.ChallengeId)

	return &adminv1.ConfirmUserMFAResponse{
		RecoveryCodes: recoveryCodes,
	}, nil
}

// DisableUserMFA 关闭 MFA
func (a *KnownAdminAPI) DisableUserMFA(ctx context.Context, req *adminv1.DisableUserMFARequest) (*emptypb.Empty, error) {
	if req.UserId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("user_id is required")
	}
	if req.TotpCode == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("totp_code is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}

	_, localProviderID, pErr := a.getLocalMFAPolicy(ctx, db)
	if pErr != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query local MFA policy")
	}
	if localProviderID == 0 {
		return nil, errs.FailedPrecondition(ctx).WithMessage("local auth provider not found")
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	identity, err := tx.UserIdentities.Query().
		Select(
			useridentities.FieldMfaEnabled,
			useridentities.FieldMfaSecretEncrypted,
			useridentities.FieldMfaRecoveryCodesEncrypted,
		).
		Where(
			useridentities.UserIDEQ(int(req.UserId)),
			useridentities.ProviderIDEQ(localProviderID),
			useridentities.MfaEnabledEQ(true),
		).
		First(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.FailedPrecondition(ctx).WithMessage("MFA is not enabled for this user")
		}
		return nil, errs.Internal(ctx).WithMessage("failed to query user identity")
	}

	verifiedByRecoveryCode := false
	recoveryCodesEncryptedAfterConsume := []byte(nil)

	secretBytes, err := crypto.DecryptAES(a.config.aesKey, identity.MfaSecretEncrypted)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to decrypt MFA secret")
	}
	if !totp.Validate(req.TotpCode, string(secretBytes)) {
		recoveryCodesEncryptedAfterConsume, verifiedByRecoveryCode, err = consumeRecoveryCodeEncrypted(a.config.aesKey, identity.MfaRecoveryCodesEncrypted, req.TotpCode, time.Now())
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to verify recovery code")
		}
		if !verifiedByRecoveryCode {
			return nil, errs.Unauthenticated(ctx).WithMessage("invalid TOTP code or recovery code")
		}

		affected, saveErr := tx.UserIdentities.Update().
			Where(
				useridentities.UserIDEQ(int(req.UserId)),
				useridentities.ProviderIDEQ(localProviderID),
				useridentities.MfaEnabledEQ(true),
				useridentities.MfaRecoveryCodesEncryptedEQ(identity.MfaRecoveryCodesEncrypted),
			).
			SetMfaRecoveryCodesEncrypted(recoveryCodesEncryptedAfterConsume).
			Save(ctx)
		if saveErr != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to consume recovery code")
		}
		if affected == 0 {
			return nil, errs.FailedPrecondition(ctx).WithMessage("recovery code already used or MFA state changed")
		}
	}

	updater := tx.UserIdentities.Update().
		Where(
			useridentities.UserIDEQ(int(req.UserId)),
			useridentities.ProviderIDEQ(localProviderID),
			useridentities.MfaEnabledEQ(true),
		)
	if verifiedByRecoveryCode {
		updater = updater.Where(useridentities.MfaRecoveryCodesEncryptedEQ(recoveryCodesEncryptedAfterConsume))
	}
	affected, err := updater.
		SetMfaEnabled(false).
		SetMfaSecretEncrypted([]byte("")).
		SetMfaRecoveryCodesEncrypted([]byte("")).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to disable MFA")
	}
	if affected == 0 {
		return nil, errs.FailedPrecondition(ctx).WithMessage("MFA state changed, please retry")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to commit MFA disable transaction")
	}

	return &emptypb.Empty{}, nil
}

// StartAuthMFASetup 登录态首次配置 MFA（开始）
func (a *KnownAdminAPI) StartAuthMFASetup(ctx context.Context, req *adminv1.StartAuthMFASetupRequest) (*adminv1.StartAuthMFASetupResponse, error) {
	if req.ChallengeId == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("challenge_id is required")
	}

	challenge, ok := a.mfaChallenges.Get(req.ChallengeId)
	if !ok {
		return nil, errs.FailedPrecondition(ctx).WithMessage("challenge expired or not found")
	}
	if challenge.ChallengeType != mfaChallengeTypeLoginSetup {
		return nil, errs.FailedPrecondition(ctx).WithMessage("invalid challenge type")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "KnownAdmin",
		AccountName: challenge.Username,
	})
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to generate TOTP key")
	}

	setupChallenge, err := a.mfaChallenges.Create(mfaChallengeTypeLoginSetupConfirm, challenge.UserID, challenge.Username)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to create setup challenge")
	}
	setupChallenge.TempSecret = key.Secret()
	a.mfaChallenges.Delete(req.ChallengeId)

	return &adminv1.StartAuthMFASetupResponse{
		Secret:           key.Secret(),
		QrUri:            key.URL(),
		SetupChallengeId: setupChallenge.ChallengeID,
	}, nil
}

// ConfirmAuthMFASetup 登录态首次配置 MFA（确认）
func (a *KnownAdminAPI) ConfirmAuthMFASetup(ctx context.Context, req *adminv1.ConfirmAuthMFASetupRequest) (*adminv1.AuthToken, error) {
	if req.SetupChallengeId == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("setup_challenge_id is required")
	}
	if req.TotpCode == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("totp_code is required")
	}

	challenge, ok := a.mfaChallenges.Get(req.SetupChallengeId)
	if !ok {
		return nil, errs.FailedPrecondition(ctx).WithMessage("challenge expired or not found")
	}
	if challenge.ChallengeType != mfaChallengeTypeLoginSetupConfirm {
		return nil, errs.FailedPrecondition(ctx).WithMessage("invalid challenge type")
	}
	if challenge.TempSecret == "" {
		return nil, errs.FailedPrecondition(ctx).WithMessage("no temporary secret in challenge")
	}

	if !totp.Validate(req.TotpCode, challenge.TempSecret) {
		attempts := a.mfaChallenges.IncrAttempts(req.SetupChallengeId)
		if attempts > mfaMaxAttempts {
			a.mfaChallenges.Delete(req.SetupChallengeId)
			return nil, errs.FailedPrecondition(ctx).WithMessage("too many attempts, please login again")
		}
		return nil, errs.Unauthenticated(ctx).WithMessage("invalid TOTP code")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	_, localProviderID, pErr := a.getLocalMFAPolicy(ctx, db)
	if pErr != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query local MFA policy")
	}
	if localProviderID == 0 {
		return nil, errs.FailedPrecondition(ctx).WithMessage("local auth provider not found")
	}

	if err := a.ensureLocalIdentity(ctx, db, challenge.UserID, challenge.Username, localProviderID); err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to ensure local identity")
	}

	secretEnc, err := crypto.EncryptAES(a.config.aesKey, []byte(challenge.TempSecret))
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to encrypt MFA secret")
	}

	_, err = db.UserIdentities.Update().
		Where(
			useridentities.UserIDEQ(challenge.UserID),
			useridentities.ProviderIDEQ(localProviderID),
		).
		SetMfaEnabled(true).
		SetMfaSecretEncrypted(secretEnc).
		SetMfaRecoveryCodesEncrypted([]byte("")).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to enable MFA for local identity")
	}

	a.mfaChallenges.Delete(req.SetupChallengeId)

	accessToken, err := a.issueTokenForUser(ctx, db, challenge.UserID)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to issue access token")
	}

	return &adminv1.AuthToken{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   24 * 60 * 60,
	}, nil
}

// issueTokenForUser 为指定用户签发 JWT access_token（MFA 验证通过后调用）
func (a *KnownAdminAPI) issueTokenForUser(ctx context.Context, db *lion.Client, userID int) (string, error) {
	u, err := db.Users.Query().
		Select(users.FieldID, users.FieldUsername, users.FieldNickname).
		Where(users.IDEQ(userID), users.UserStatusEQ(int(adminv1.User_ACTIVE.Number()))).
		Only(ctx)
	if err != nil {
		return "", fmt.Errorf("user not found or not active: %w", err)
	}

	sk, err := db.Credentials.Query().
		Select(credentials.FieldPrivateKeyEncrypted).
		Only(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to query credentials: %w", err)
	}

	derBytes, err := crypto.DecryptAES(a.config.aesKey, sk.PrivateKeyEncrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt private key: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	var groups []string
	rs, err := db.UserRoles.Query().
		Select(userroles.FieldRoleID, userroles.FieldUserID).
		Where(userroles.UserIDEQ(userID)).
		WithLionRoles().
		All(ctx)
	if err == nil {
		for _, r := range rs {
			if r.Edges.LionRoles != nil {
				groups = append(groups, r.Edges.LionRoles.Code)
			}
		}
	}

	idToken := &auth.IDTokenClaims{
		Username: u.Username,
		Nickname: u.Nickname,
	}
	idToken.SetSubject(strconv.Itoa(u.ID))
	idToken.SetGroups(groups)
	idToken.SetExpiresAt(24 * 60 * 60)
	idToken.SetEmail(fmt.Sprintf("%v@localhost", u.Username))

	return idToken.GetAccessTokenRSA(privateKey)
}

func generateRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		codes[i] = hex.EncodeToString(b)
	}
	return codes, nil
}

type mfaRecoveryCodesState struct {
	Version int                   `json:"version"`
	Items   []mfaRecoveryCodeItem `json:"items"`
}

type mfaRecoveryCodeItem struct {
	Hash   string     `json:"hash"`
	Used   bool       `json:"used"`
	UsedAt *time.Time `json:"used_at,omitempty"`
}

func encryptRecoveryCodes(aesKey []byte, recoveryCodes []string) ([]byte, error) {
	items := make([]mfaRecoveryCodeItem, 0, len(recoveryCodes))
	for _, code := range recoveryCodes {
		items = append(items, mfaRecoveryCodeItem{
			Hash: hashRecoveryCode(aesKey, code),
			Used: false,
		})
	}
	payload, err := json.Marshal(mfaRecoveryCodesState{
		Version: 1,
		Items:   items,
	})
	if err != nil {
		return nil, err
	}
	return crypto.EncryptAES(aesKey, payload)
}

func consumeRecoveryCodeEncrypted(aesKey, encrypted []byte, inputCode string, now time.Time) ([]byte, bool, error) {
	if len(encrypted) == 0 {
		return nil, false, nil
	}
	raw, err := crypto.DecryptAES(aesKey, encrypted)
	if err != nil {
		return nil, false, err
	}

	var state mfaRecoveryCodesState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, false, err
	}
	if state.Version != 1 {
		return nil, false, fmt.Errorf("unsupported recovery code state version: %d", state.Version)
	}

	inputHash := hashRecoveryCode(aesKey, inputCode)
	matched := false
	for idx := range state.Items {
		if state.Items[idx].Hash != inputHash {
			continue
		}
		if state.Items[idx].Used {
			return nil, false, nil
		}
		state.Items[idx].Used = true
		usedAt := now
		state.Items[idx].UsedAt = &usedAt
		matched = true
		break
	}
	if !matched {
		return nil, false, nil
	}

	nextRaw, err := json.Marshal(state)
	if err != nil {
		return nil, false, err
	}
	nextEncrypted, err := crypto.EncryptAES(aesKey, nextRaw)
	if err != nil {
		return nil, false, err
	}
	return nextEncrypted, true, nil
}

func hashRecoveryCode(aesKey []byte, code string) string {
	h := sha256.New()
	h.Write([]byte("mfa-recovery-code:v1:"))
	h.Write(aesKey)
	h.Write([]byte{':'})
	h.Write([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeRecoveryCode(code string) string {
	normalized := strings.TrimSpace(strings.ToLower(code))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	return normalized
}
