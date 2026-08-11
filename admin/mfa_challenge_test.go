package admin

import (
	"testing"
	"time"
)

func TestMFAChallengePreservesAndCopiesIssuanceContext(t *testing.T) {
	store := newMFAChallengeStore()
	t.Cleanup(func() { close(store.stopGC) })

	issuance := AccessTokenIssuanceContext{
		ClientID: "admin-web",
		Scope:    "openid profile",
		Tenant:   "default",
		TTL:      time.Hour,
	}
	challenge, err := store.CreateLoginWithTTL(time.Minute, mfaChallengeTypeLoginVerify, 42, "alice", issuance)
	if err != nil {
		t.Fatal(err)
	}
	challenge.IssuanceContext.ClientID = "mutated-return-value"

	stored, ok := store.Get(challenge.ChallengeID)
	if !ok {
		t.Fatal("challenge not found")
	}
	if stored.IssuanceContext == nil || stored.IssuanceContext.ClientID != "admin-web" {
		t.Fatalf("issuance context was not copied: %+v", stored.IssuanceContext)
	}
	if stored.IssuanceContext.ClientID != "admin-web" || stored.IssuanceContext.TTL != time.Hour {
		t.Fatalf("issuance context mismatch: %+v", stored.IssuanceContext)
	}

	stored.IssuanceContext.ClientID = "mutated-get"
	again, ok := store.Get(challenge.ChallengeID)
	if !ok || again.IssuanceContext.ClientID != "admin-web" {
		t.Fatalf("Get returned mutable store state: %+v", again)
	}

	store.Delete(challenge.ChallengeID)
	if _, ok := store.Get(challenge.ChallengeID); ok {
		t.Fatal("deleted challenge remains usable")
	}
}

func TestMFAChallengeAcquireIsSingleConsumer(t *testing.T) {
	store := newMFAChallengeStore()
	challenge, err := store.CreateBoundWithTTL(time.Minute, mfaChallengeTypeAdminSetup, 42, "alice", "session-a")
	if err != nil {
		t.Fatalf("CreateBoundWithTTL: %v", err)
	}

	acquired, ok := store.Acquire(challenge.ChallengeID)
	if !ok || acquired.SessionID != "session-a" {
		t.Fatalf("first Acquire() = (%+v, %v)", acquired, ok)
	}
	if _, ok := store.Acquire(challenge.ChallengeID); ok {
		t.Fatal("concurrent Acquire() unexpectedly succeeded")
	}
	store.Release(challenge.ChallengeID)
	if _, ok := store.Acquire(challenge.ChallengeID); !ok {
		t.Fatal("Acquire() should succeed after Release()")
	}
	store.Delete(challenge.ChallengeID)
	if _, ok := store.Acquire(challenge.ChallengeID); ok {
		t.Fatal("deleted challenge was acquired")
	}
}

func TestMFAChallengeDeleteByUserID(t *testing.T) {
	store := newMFAChallengeStore()
	t.Cleanup(func() { close(store.stopGC) })

	userOneLogin, err := store.CreateWithTTL(time.Minute, mfaChallengeTypeLoginVerify, 41, "alice")
	if err != nil {
		t.Fatalf("create user-one login challenge: %v", err)
	}
	userOneSetup, err := store.CreateWithTTL(time.Minute, mfaChallengeTypeLoginSetup, 41, "alice")
	if err != nil {
		t.Fatalf("create user-one setup challenge: %v", err)
	}
	userTwoLogin, err := store.CreateWithTTL(time.Minute, mfaChallengeTypeLoginVerify, 42, "bob")
	if err != nil {
		t.Fatalf("create user-two login challenge: %v", err)
	}

	store.DeleteByUserID(41)

	if _, ok := store.Get(userOneLogin.ChallengeID); ok {
		t.Fatal("target user's login challenge remains usable")
	}
	if _, ok := store.Get(userOneSetup.ChallengeID); ok {
		t.Fatal("target user's setup challenge remains usable")
	}
	if _, ok := store.Get(userTwoLogin.ChallengeID); !ok {
		t.Fatal("another user's challenge was deleted")
	}

	// Repeating the operation is intentionally harmless.
	store.DeleteByUserID(41)
}
