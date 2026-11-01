package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"golang.org/x/oauth2"
)

var (
	errExternalUsernameConflict = errors.New("external username is unavailable")
	errExternalLoginRejected    = errors.New("external login is unavailable")
	localUsernamePattern        = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	providerUsernamePattern     = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)
)

type externalProvisioningInput struct {
	Subject         string
	Username        string
	CanLinkUsername bool
	LegacyUsername  string
	Wechat          bool
	UnionID         string
	Contacts        verifiedIdentityClaims
	Token           *oauth2.Token
	CreateUser      func(context.Context, *lion.Tx, string) (*lion.Users, error)
}

type externalCredentials struct {
	Access  []byte
	Refresh []byte
	Expiry  time.Time
}

func (s *socialUsers) prepareExternalCredentials(token *oauth2.Token) (externalCredentials, error) {
	var credentials externalCredentials
	if token == nil {
		return credentials, nil
	}
	var err error
	if token.AccessToken != "" {
		credentials.Access, err = crypto.EncryptAES(s.aesKey, []byte(token.AccessToken))
		if err != nil {
			return externalCredentials{}, fmt.Errorf("encrypt external access token: %w", err)
		}
	}
	if token.RefreshToken != "" {
		credentials.Refresh, err = crypto.EncryptAES(s.aesKey, []byte(token.RefreshToken))
		if err != nil {
			return externalCredentials{}, fmt.Errorf("encrypt external refresh token: %w", err)
		}
	}
	credentials.Expiry = token.Expiry
	return credentials, nil
}

func (s *socialUsers) requireActiveProvider(ctx context.Context, db *lion.Client) error {
	active, err := db.AuthProviders.Query().Where(
		authproviders.IDEQ(s.AuthProvider.ID),
		authproviders.ProviderStatusEQ(int(adminv1.AuthProvider_ACTIVE)),
		authproviders.DeletedAtIsNil(),
	).Exist(ctx)
	if err != nil {
		return err
	}
	if !active {
		return errExternalLoginRejected
	}
	return nil
}

func (s *socialUsers) requireActiveExternalUser(ctx context.Context, db *lion.Client, userID int) error {
	if err := s.requireActiveProvider(ctx, db); err != nil {
		return err
	}
	active, err := db.Users.Query().Where(users.IDEQ(userID), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).Exist(ctx)
	if err != nil {
		return err
	}
	if !active {
		return errExternalLoginRejected
	}
	return nil
}

// resolveExternalUser preserves authoritative bindings before reading any new
// naming policy. Only unbound identities enter the provisioning transaction.
func (s *socialUsers) resolveExternalUser(ctx context.Context, input externalProvisioningInput) (int, error) {
	if input.Subject == "" {
		return 0, errExternalLoginRejected
	}
	if err := s.requireActiveProvider(ctx, s.db); err != nil {
		return 0, err
	}
	identity, err := s.db.UserIdentities.Query().Where(
		useridentities.ProviderIDEQ(s.AuthProvider.ID), useridentities.ProviderUserIDEQ(input.Subject),
	).Only(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return 0, err
	}
	credentials, credentialErr := s.prepareExternalCredentials(input.Token)
	if credentialErr != nil {
		return 0, credentialErr
	}
	if identity != nil {
		if err := s.requireActiveExternalUser(ctx, s.db, identity.UserID); err != nil {
			return 0, err
		}
		if err := s.refreshExternalIdentity(ctx, s.db, identity, input, credentials); err != nil {
			return 0, err
		}
		return identity.UserID, nil
	}
	policy, err := readIdentityPolicy(ctx, s.db.GlobalSettings.Query())
	if err != nil {
		return 0, err
	}
	if input.Username != "" {
		if err := validateExternalUsername(input, policy); err != nil {
			return 0, err
		}
	}
	for attempt := range identityTransactionAttempts {
		userID, err := s.provisionExternalIdentity(ctx, input, policy, credentials)
		if err == nil {
			return userID, nil
		}
		if !lion.IsConstraintError(err) && !retryableDatabaseError(err) {
			return 0, err
		}
		// A competing request may already have committed the subject. Reread
		// outside the rolled-back transaction, never attach by a guessed name.
		identity, queryErr := s.db.UserIdentities.Query().Where(
			useridentities.ProviderIDEQ(s.AuthProvider.ID), useridentities.ProviderUserIDEQ(input.Subject),
		).Only(ctx)
		if queryErr == nil {
			if err := s.requireActiveExternalUser(ctx, s.db, identity.UserID); err != nil {
				return 0, err
			}
			if err := s.refreshExternalIdentity(ctx, s.db, identity, input, credentials); err != nil {
				return 0, err
			}
			return identity.UserID, nil
		}
		if !lion.IsNotFound(queryErr) {
			return 0, queryErr
		}
		if lion.IsConstraintError(err) {
			if conflictErr := s.externalContactConstraint(ctx, input.Contacts); conflictErr != nil {
				return 0, conflictErr
			}
		}
		if attempt+1 == identityTransactionAttempts {
			return 0, errExternalLoginRejected
		}
	}
	return 0, errExternalLoginRejected
}

func validateExternalUsername(input externalProvisioningInput, policy identityPolicy) error {
	if policy.UsernameStrategy == usernameProviderPrefixed {
		return nil
	}
	if input.Username == "" {
		if policy.UsernameStrategy == usernameExternalStrict {
			return errExternalUsernameConflict
		}
		return nil
	}
	if len(input.Username) > 255 || !localUsernamePattern.MatchString(input.Username) {
		return errExternalUsernameConflict
	}
	return nil
}

func (s *socialUsers) provisionExternalIdentity(ctx context.Context, input externalProvisioningInput, policy identityPolicy, credentials externalCredentials) (int, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	db := tx.Client()
	if err := s.requireActiveProvider(ctx, db); err != nil {
		return 0, err
	}
	identity, err := tx.UserIdentities.Query().Where(
		useridentities.ProviderIDEQ(s.AuthProvider.ID), useridentities.ProviderUserIDEQ(input.Subject),
	).Only(ctx)
	if err == nil {
		if err := s.requireActiveExternalUser(ctx, db, identity.UserID); err != nil {
			return 0, err
		}
		if err := s.refreshExternalIdentity(ctx, db, identity, input, credentials); err != nil {
			return 0, err
		}
		return identity.UserID, tx.Commit()
	}
	if !lion.IsNotFound(err) {
		return 0, err
	}
	target, linked, err := s.collectExternalIdentityTarget(ctx, tx, input, policy)
	if err != nil {
		return 0, err
	}
	if !linked {
		if err := validateExternalUsername(input, policy); err != nil {
			return 0, err
		}
		username, err := s.allocateExternalUsername(ctx, tx, input, policy)
		if err != nil {
			return 0, err
		}
		newUser, err := input.CreateUser(ctx, tx, username)
		if err != nil {
			return 0, err
		}
		target = newUser.ID
		if err := s.ensureUnassignedDepartmentMembership(ctx, tx, target); err != nil {
			return 0, err
		}
	}
	// One local account may have only one subject from this provider.
	occupied, err := tx.UserIdentities.Query().Where(useridentities.ProviderIDEQ(s.AuthProvider.ID), useridentities.UserIDEQ(target)).Exist(ctx)
	if err != nil {
		return 0, err
	}
	if occupied {
		return 0, errExternalIdentityAlreadyBound
	}
	create := tx.UserIdentities.Create().SetProviderID(s.AuthProvider.ID).SetProviderUserID(input.Subject).SetUserID(target)
	if len(credentials.Access) > 0 {
		create.SetAccessTokenEncrypted(credentials.Access)
	}
	if len(credentials.Refresh) > 0 {
		create.SetRefreshTokenEncrypted(credentials.Refresh)
	}
	if !credentials.Expiry.IsZero() {
		create.SetTokenExpiresAt(credentials.Expiry)
	}
	if input.Wechat && strings.TrimSpace(input.UnionID) != "" {
		create.SetProviderUnionID(strings.TrimSpace(input.UnionID))
	}
	if _, err := create.Save(ctx); err != nil {
		return 0, err
	}
	if err := s.requireActiveExternalUser(ctx, db, target); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if s.logger != nil {
		s.logger.InfoContext(ctx, "external identity provisioned", "provider", s.ProviderName, "user_id", target, "linked", linked, "username_strategy", policy.UsernameStrategy)
	}
	return target, nil
}

func (s *socialUsers) collectExternalIdentityTarget(ctx context.Context, tx *lion.Tx, input externalProvisioningInput, policy identityPolicy) (int, bool, error) {
	contactID, contactFound, err := s.verifiedIdentifierTarget(ctx, tx, input.Contacts, policy.LinkByContact)
	if err != nil {
		return 0, false, err
	}
	if !policy.LinkByUsername || !input.CanLinkUsername || input.Username == "" {
		return contactID, contactFound, nil
	}
	if s.isReservedUsername(input.Username) {
		return 0, false, errExternalUsernameConflict
	}
	target, err := tx.Users.Query().Where(users.UsernameEQ(input.Username)).Only(ctx)
	if lion.IsNotFound(err) {
		return contactID, contactFound, nil
	}
	if err != nil {
		return 0, false, err
	}
	if target.Username != input.Username {
		// A collation-equivalent spelling occupies the name but proves no
		// identity equality. Allocation handles it as an ordinary collision.
		return contactID, contactFound, nil
	}
	if contactFound && target.ID != contactID {
		return 0, false, errExternalVerifiedIdentifiersConflict
	}
	if target.DeletedAt != nil || target.UserStatus != int(adminv1.User_ACTIVE) || target.UserType == int(adminv1.User_ADMIN) || target.UserType == int(adminv1.User_SYSTEM) {
		return 0, false, errExternalUsernameConflict
	}
	if s.staticUsers != nil {
		if _, found := s.staticUsers.Find(target.Username); found {
			return 0, false, errExternalUsernameConflict
		}
		if _, found := s.staticUsers.FindByUserID(int64(target.ID)); found {
			return 0, false, errExternalUsernameConflict
		}
	}
	roleIDs, err := effectiveRoleIDsForUserAt(ctx, tx.Client(), target.ID, time.Now())
	if err != nil {
		return 0, false, err
	}
	codes, err := roleCodesForIDs(ctx, tx.Client(), roleIDs)
	if err != nil {
		return 0, false, err
	}
	if slices.Contains(codes, seedRoleCode(adminv1.RoleCode_ROLE_CODE_ADMIN)) || slices.Contains(codes, seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)) {
		return 0, false, errExternalUsernameConflict
	}
	return target.ID, true, nil
}

func (s *socialUsers) allocateExternalUsername(ctx context.Context, tx *lion.Tx, input externalProvisioningInput, policy identityPolicy) (string, error) {
	provider := s.ProviderName
	if policy.UsernameStrategy == usernameProviderPrefixed {
		if input.Wechat {
			candidate := strings.ToLower(provider + "_" + input.LegacyUsername)
			occupied, err := tx.Users.Query().Where(users.UsernameEQ(candidate)).Exist(ctx)
			if err != nil {
				return "", err
			}
			if occupied {
				return "", errExternalUsernameConflict
			}
			return candidate, nil
		}
		return findAvailableUsername(ctx, tx, buildLDAPLocalUsernameBase(provider, input.LegacyUsername), nil)
	}
	if input.Username != "" {
		occupied, err := tx.Users.Query().Where(users.UsernameEQ(input.Username)).Exist(ctx)
		if err != nil {
			return "", err
		}
		if !occupied && !s.isReservedUsername(input.Username) {
			return input.Username, nil
		}
		if policy.UsernameStrategy == usernameExternalStrict {
			return "", errExternalUsernameConflict
		}
	}
	safeProvider := providerUsernamePattern.ReplaceAllString(provider, "_")
	source := input.Username
	if source == "" {
		source = sanitizeUsernamePart(input.Subject)
		if source == "" {
			source = "user"
		}
	}
	return findAvailableUsername(ctx, tx, safeProvider+"_"+source, s.isReservedUsername)
}

func (s *socialUsers) refreshExternalIdentity(ctx context.Context, db *lion.Client, identity *lion.UserIdentities, input externalProvisioningInput, credentials externalCredentials) error {
	update := db.UserIdentities.UpdateOneID(identity.ID)
	changed := false
	if len(credentials.Access) > 0 {
		update.SetAccessTokenEncrypted(credentials.Access)
		changed = true
	}
	if len(credentials.Refresh) > 0 {
		update.SetRefreshTokenEncrypted(credentials.Refresh)
		changed = true
	}
	if !credentials.Expiry.IsZero() {
		update.SetTokenExpiresAt(credentials.Expiry)
		changed = true
	}
	if input.Wechat {
		value, persist, conflict := reconcileWechatUnionID(identity.ProviderUnionID, input.UnionID)
		if conflict && s.logger != nil {
			s.logger.WarnContext(ctx, "WeChat UnionID mismatch; keeping stored value", "provider", s.ProviderName, "identity_id", identity.ID)
		}
		if persist {
			update.SetProviderUnionID(value)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return update.Exec(ctx)
}

// Constraint checks run only after rollback and the authoritative subject reread.
func (s *socialUsers) externalContactConstraint(ctx context.Context, contacts verifiedIdentityClaims) error {
	hashes := s.canonicalVerifiedIdentifierHashes(ctx, contacts)
	if hashes.email != "" {
		occupied, err := s.db.Users.Query().Where(users.EmailHashEQ(hashes.email)).Exist(ctx)
		if err != nil {
			return err
		}
		if occupied {
			return errExternalEmailAlreadyExists
		}
	}
	if hashes.phone != "" {
		occupied, err := s.db.Users.Query().Where(users.PhoneNumberHashEQ(hashes.phone)).Exist(ctx)
		if err != nil {
			return err
		}
		if occupied {
			return errExternalPhoneAlreadyExists
		}
	}
	return nil
}

func (s *socialUsers) isReservedUsername(username string) bool {
	if s.staticUsers == nil {
		return false
	}
	_, found := s.staticUsers.Find(username)
	return found
}
