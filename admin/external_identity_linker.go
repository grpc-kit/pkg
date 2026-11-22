package admin

import (
	"context"
	"fmt"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/users"
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

// verifiedIdentifierTarget resolves candidates without changing any identity.
func (s *socialUsers) verifiedIdentifierTarget(ctx context.Context, tx *lion.Tx, claims verifiedIdentityClaims, enabled bool) (int, bool, error) {
	if !enabled {
		return 0, false, nil
	}
	hashes := s.canonicalVerifiedIdentifierHashes(ctx, claims)
	emailID, emailFound, err := queryVerifiedIdentifierOwner(ctx, tx, hashes.email, users.EmailHashEQ, users.EmailVerifiedEQ(true), "email", errExternalEmailAlreadyExists)
	if err != nil {
		return 0, false, err
	}
	phoneID, phoneFound, err := queryVerifiedIdentifierOwner(ctx, tx, hashes.phone, users.PhoneNumberHashEQ, users.PhoneNumberVerifiedEQ(true), "phone number", errExternalPhoneAlreadyExists)
	if err != nil {
		return 0, false, err
	}
	return convergeVerifiedIdentifierOwners(emailID, emailFound, phoneID, phoneFound)
}

func (s *socialUsers) canonicalVerifiedIdentifierHashes(ctx context.Context, claims verifiedIdentityClaims) verifiedIdentifierHashes {
	var hashes verifiedIdentifierHashes
	if claims.EmailVerified && strings.TrimSpace(claims.Email) != "" {
		identifier, err := canonicalizeEmailIdentifier(claims.Email)
		if err != nil {
			if s.logger != nil {
				s.logger.WarnContext(ctx, "ignore invalid verified email claim", "provider", s.ProviderName, "error", err)
			}
		} else {
			hashes.email = identifier.Hash
		}
	}
	if claims.PhoneNumberVerified && strings.TrimSpace(claims.PhoneNumber) != "" {
		identifier, err := canonicalizeE164PhoneIdentifier(claims.PhoneNumber)
		if err != nil {
			if s.logger != nil {
				s.logger.WarnContext(ctx, "ignore invalid verified phone claim", "provider", s.ProviderName, "error", err)
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
