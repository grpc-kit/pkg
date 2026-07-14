package crypto

import (
	"crypto/sha1"
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

// SHA1 返回数据的 SHA-1 摘要的十六进制表示（40 字符）。
// 用于 key_id (kid) 标识符生成，与 Google OIDC provider 的 JWKS kid 风格一致。
func SHA1(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	hash := sha1.Sum(data)
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
