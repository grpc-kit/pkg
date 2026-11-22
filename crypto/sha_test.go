package crypto

import (
	"fmt"
	"testing"
)

func TestUsername2UserID(t *testing.T) {
	for name, want := range map[string]int64{"oneops": 101705, "user1": 108137} {
		if got := Username2UserID(name); got != want {
			t.Errorf("%s: ID = %d, want %d", name, got, want)
		}
	}
	for i := range 20000 {
		name := fmt.Sprintf("service-%d", i)
		if id := Username2UserID(name); id < 100000 || id > 109999 {
			t.Fatalf("derived ID outside static range: %d", id)
		}
	}
}

func TestResolveStaticUserID(t *testing.T) {
	for _, id := range []int64{0, 101705} {
		got, err := ResolveStaticUserID("oneops", id)
		if err != nil || got != 101705 {
			t.Fatalf("resolve %d: ID=%d, err=%v", id, got, err)
		}
	}
	for _, id := range []int64{-1, 1, 99999, 100000, 109999, 110000, 123455, 123456, 200000} {
		if _, err := ResolveStaticUserID("oneops", id); err == nil {
			t.Errorf("accepted invalid explicit ID %d", id)
		}
	}
	for _, name := range []string{"", " \t"} {
		if _, err := ResolveStaticUserID(name, 0); err == nil {
			t.Error("accepted empty username")
		}
	}
}
