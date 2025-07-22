package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

func SHA256(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
