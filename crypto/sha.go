package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
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
