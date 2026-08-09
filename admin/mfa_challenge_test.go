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
