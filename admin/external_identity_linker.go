package admin

import (
	"context"
	"fmt"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"golang.org/x/oauth2"
)

type verifiedIdentityClaims struct {
	Email               string
	EmailVerified       bool
	PhoneNumber         string
	PhoneNumberVerified bool
}

type verifiedIdentifierHashes struct {
	email string
	phone string
}

// linkExternalIdentityByVerifiedIdentifiers links an external identity only
// when all verified identifier matches converge on one active local user. The
// caller owns the transaction and commits it when linked is true.
func (s *socialUsers) linkExternalIdentityByVerifiedIdentifiers(
	ctx context.Context,
	tx *lion.Tx,
	providerUserID string,
	claims verifiedIdentityClaims,
	autoLinkEnabled bool,
	token *oauth2.Token,
) (userID int, linked bool, err error) {
	if !autoLinkEnabled {
		return 0, false, nil
	}

	hashes := s.canonicalVerifiedIdentifierHashes(claims)
	if hashes.email == "" && hashes.phone == "" {
		return 0, false, nil
	}

	emailUserID, emailFound, err := queryVerifiedIdentifierOwner(
		ctx,
		tx,
		hashes.email,
		users.EmailHashEQ,
		users.EmailVerifiedEQ(true),
		"email",
		errExternalEmailAlreadyExists,
	)
	if err != nil {
		return 0, false, err
	}
	phoneUserID, phoneFound, err := queryVerifiedIdentifierOwner(
		ctx,
		tx,
		hashes.phone,
		users.PhoneNumberHashEQ,
		users.PhoneNumberVerifiedEQ(true),
		"phone number",
		errExternalPhoneAlreadyExists,
	)
	if err != nil {
		return 0, false, err
	}

	targetUserID, found, err := convergeVerifiedIdentifierOwners(
		emailUserID,
		emailFound,
		phoneUserID,
		phoneFound,
	)
	if err != nil || !found {
		return 0, false, err
	}

	bySubject, err := tx.UserIdentities.Query().
		Select(
			useridentities.FieldID,
			useridentities.FieldUserID,
			useridentities.FieldProviderUserID,
		).
		Where(
			useridentities.ProviderIDEQ(s.AuthProvider.ID),
			useridentities.ProviderUserIDEQ(providerUserID),
		).
		Only(ctx)
	if err == nil {
		if bySubject.UserID == targetUserID {
			return targetUserID, true, nil
		}
		return 0, false, errExternalIdentityAlreadyBound
	}
	if !lion.IsNotFound(err) {
		return 0, false, fmt.Errorf("check external subject binding: %w", err)
	}

	byProvider, err := tx.UserIdentities.Query().
		Select(
			useridentities.FieldID,
			useridentities.FieldUserID,
			useridentities.FieldProviderUserID,
		).
		Where(
			useridentities.UserIDEQ(targetUserID),
			useridentities.ProviderIDEQ(s.AuthProvider.ID),
		).
		Only(ctx)
	if err == nil {
		if byProvider.ProviderUserID == providerUserID {
			return targetUserID, true, nil
		}
		return 0, false, errExternalIdentityAlreadyBound
	}
	if !lion.IsNotFound(err) {
		return 0, false, fmt.Errorf("check user provider binding: %w", err)
	}

	identityCreate := tx.UserIdentities.Create().
		SetUserID(targetUserID).
		SetProviderID(s.AuthProvider.ID).
		SetProviderUserID(providerUserID)
	if token != nil {
		if token.AccessToken != "" {
			accessTokenEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(token.AccessToken))
			if encryptErr != nil {
				return 0, false, fmt.Errorf("encrypt linked access token: %w", encryptErr)
			}
			identityCreate.SetAccessTokenEncrypted(accessTokenEnc)
		}
		if token.RefreshToken != "" {
			refreshTokenEnc, encryptErr := crypto.EncryptAES(s.aesKey, []byte(token.RefreshToken))
			if encryptErr != nil {
				return 0, false, fmt.Errorf("encrypt linked refresh token: %w", encryptErr)
			}
			identityCreate.SetRefreshTokenEncrypted(refreshTokenEnc)
		}
		if !token.Expiry.IsZero() {
			identityCreate.SetTokenExpiresAt(token.Expiry)
		}
	}

	if _, err := identityCreate.Save(ctx); err != nil {
		if lion.IsConstraintError(err) {
			return 0, false, errExternalIdentityAlreadyBound
		}
		return 0, false, fmt.Errorf("create verified identifier identity binding: %w", err)
	}
	if s.logger != nil {
		s.logger.Infof(
			"external identity verified identifier auto-link success: provider=%s user_id=%d",
			s.ProviderName,
			targetUserID,
		)
	}
	return targetUserID, true, nil
}

func (s *socialUsers) canonicalVerifiedIdentifierHashes(claims verifiedIdentityClaims) verifiedIdentifierHashes {
	var hashes verifiedIdentifierHashes
	if claims.EmailVerified && strings.TrimSpace(claims.Email) != "" {
		identifier, err := canonicalizeEmailIdentifier(claims.Email)
		if err != nil {
			if s.logger != nil {
				s.logger.Warnf("ignore invalid verified email claim: provider=%s err=%v", s.ProviderName, err)
			}
		} else {
			hashes.email = identifier.Hash
		}
	}
	if claims.PhoneNumberVerified && strings.TrimSpace(claims.PhoneNumber) != "" {
		identifier, err := canonicalizeE164PhoneIdentifier(claims.PhoneNumber)
		if err != nil {
			if s.logger != nil {
				s.logger.Warnf("ignore invalid verified phone claim: provider=%s err=%v", s.ProviderName, err)
			}
		} else {
			hashes.phone = identifier.Hash
		}
	}
	return hashes
}

func queryVerifiedIdentifierOwner(
	ctx context.Context,
	tx *lion.Tx,
	hash string,
	hashPredicate func(string) predicate.Users,
	verifiedPredicate predicate.Users,
	identifierName string,
	occupiedError error,
) (userID int, found bool, err error) {
	if hash == "" {
		return 0, false, nil
	}

	userID, err = tx.Users.Query().
		Where(
			hashPredicate(hash),
			verifiedPredicate,
			users.UserStatusEQ(int(adminv1.User_ACTIVE.Number())),
			users.DeletedAtIsNil(),
		).
		OnlyID(ctx)
	if err == nil {
		return userID, true, nil
	}
	if !lion.IsNotFound(err) {
		return 0, false, fmt.Errorf("resolve verified %s owner: %w", identifierName, err)
	}

	// An unverified, inactive, or deleted row may still own the unique hash. It
	// cannot be selected for auto-link and must not be bypassed by provisioning.
	if _, occupiedErr := tx.Users.Query().
		Where(hashPredicate(hash)).
		OnlyID(ctx); occupiedErr == nil || lion.IsNotSingular(occupiedErr) {
		return 0, false, occupiedError
	} else if !lion.IsNotFound(occupiedErr) {
		return 0, false, fmt.Errorf("check verified %s ownership conflict: %w", identifierName, occupiedErr)
	}
	return 0, false, nil
}

func convergeVerifiedIdentifierOwners(
	emailUserID int,
	emailFound bool,
	phoneUserID int,
	phoneFound bool,
) (userID int, found bool, err error) {
	switch {
	case emailFound && phoneFound && emailUserID != phoneUserID:
		return 0, false, errExternalVerifiedIdentifiersConflict
	case emailFound:
		return emailUserID, true, nil
	case phoneFound:
		return phoneUserID, true, nil
	default:
		return 0, false, nil
	}
}

func (s *socialUsers) identityAutoLinkEnabled(ctx context.Context) (bool, error) {
	enabled, _, err := newGlobalSettingsReader(s.logger, s.db).GetBool(
		ctx,
		globalSettingsCategorySecurity,
		globalSettingKeyIdentityAutoLink,
	)
	if err != nil {
		return false, fmt.Errorf("read identity auto-link setting: %w", err)
	}
	return enabled, nil
}
