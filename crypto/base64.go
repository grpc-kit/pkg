package crypto

import "encoding/base64"

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(data []byte) []byte {
	val, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return []byte("")
	}

	return val
}
