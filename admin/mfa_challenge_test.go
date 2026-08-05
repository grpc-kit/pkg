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
