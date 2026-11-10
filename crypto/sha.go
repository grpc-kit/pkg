package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"strings"
)

func SHA256(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func Username2UserID(username string) int64 {
	var maxVal, minVal int64
	maxVal = 109999
	minVal = 100000

	h := fnv.New64a()
	h.Write([]byte(username))
	v := int64(h.Sum64() & 0x7fffffffffffffff)
	return minVal + (v % (maxVal - minVal + 1))
}

// ResolveStaticUserID keeps configured static identities in the username's
// deterministic ID slot. Zero means that no explicit ID was configured.
func ResolveStaticUserID(username string, configuredID int64) (int64, error) {
	if strings.TrimSpace(username) == "" {
		return 0, fmt.Errorf("static username must not be empty")
	}
	derived := Username2UserID(username)
	if configuredID != 0 && configuredID != derived {
		return 0, fmt.Errorf("static user_id must be zero or the username-derived ID %d", derived)
	}
	return derived, nil
}
