package cfg

import (
	"testing"

	"github.com/grpc-kit/pkg/crypto"
)

func TestBasicAuthEffectivePasswordHash(t *testing.T) {
	secret := "pass1"
	wantSHA := crypto.SHA256([]byte(secret))

	t.Run("nil", func(t *testing.T) {
		if basicAuthEffectivePasswordHash(nil) != "" {
			t.Fatalf("expected empty")
		}
	})

	t.Run("password_only", func(t *testing.T) {
		got := basicAuthEffectivePasswordHash(&BasicAuth{Password: secret})
		if got != wantSHA {
			t.Fatalf("got %q want %q", got, wantSHA)
		}
	})

	t.Run("whitespace_password_hash_falls_back_to_password", func(t *testing.T) {
		got := basicAuthEffectivePasswordHash(&BasicAuth{PasswordHash: "   \t", Password: secret})
		if got != wantSHA {
			t.Fatalf("got %q want %q", got, wantSHA)
		}
	})

	t.Run("password_hash_wins_over_password", func(t *testing.T) {
		explicit := "deadbeef"
		got := basicAuthEffectivePasswordHash(&BasicAuth{PasswordHash: explicit, Password: secret})
		if got != explicit {
			t.Fatalf("got %q want %q", got, explicit)
		}
	})

	t.Run("trim_password_hash", func(t *testing.T) {
		got := basicAuthEffectivePasswordHash(&BasicAuth{PasswordHash: "  abc  "})
		if got != "abc" {
			t.Fatalf("got %q want abc", got)
		}
	})
}
