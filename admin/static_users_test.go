package admin

import (
	"testing"

	"github.com/grpc-kit/pkg/crypto"
)

func TestStaticUsersValid(t *testing.T) {
	plain := "mysecret"
	clientPayload := crypto.SHA256([]byte(plain))
	users := StaticUsers{
		&StaticUser{Username: "u1", PasswordHash: clientPayload},
	}

	u, ok := users.Valid("u1", clientPayload)
	if !ok || u == nil || u.Username != "u1" {
		t.Fatalf("sha256 hex user: ok=%v u=%v", ok, u)
	}

	_, ok = users.Valid("u1", "wrong")
	if ok {
		t.Fatal("expected mismatch")
	}

	bcryptStored := crypto.BcryptHashMust(clientPayload)
	users2 := StaticUsers{
		&StaticUser{Username: "u2", PasswordHash: bcryptStored},
	}
	u2, ok2 := users2.Valid("u2", clientPayload)
	if !ok2 || u2 == nil {
		t.Fatalf("bcrypt user: ok=%v u=%v", ok2, u2)
	}
}
