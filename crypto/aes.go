package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// 定义最小密文长度常量
const minGCMCipherTextLength = 12 // GCM 密文至少需要 12 字节（包括 nonce）

// validateAESKey 验证 AES 密钥是否合法
func validateAESKey(aesKey []byte) error {
	if len(aesKey) == 0 {
		return fmt.Errorf("AES key cannot be empty")
	}

	switch len(aesKey) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("invalid AES key length: %d, must be 16, 24, or 32 bytes", len(aesKey))
	}
}

// initializeCipher 初始化 AES 加密块
func initializeCipher(aesKey []byte) (cipher.Block, error) {
	if err := validateAESKey(aesKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	return block, nil
}

// EncryptAES 对字符串进行 AES 加密
func EncryptAES(aesKey, plainText []byte) ([]byte, error) {
	if len(plainText) == 0 {
		// return nil, fmt.Errorf("plain text cannot be empty")
		return []byte(""), nil
	}

	block, err := initializeCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce (possible system resource issue): %w", err)
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	return cipherText, nil
}

// DecryptAES 对 AES 加密字符串解密
func DecryptAES(aesKey, cipherText []byte) ([]byte, error) {
	if len(cipherText) == 0 {
		// return nil, fmt.Errorf("cipher text cannot be empty")
		return []byte(""), nil
	}

	block, err := initializeCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize+minGCMCipherTextLength {
		return nil, fmt.Errorf("invalid cipher text length: %d, must be at least %d bytes", len(cipherText), nonceSize+minGCMCipherTextLength)
	}

	nonce := cipherText[:nonceSize]
	plaintext, err := gcm.Open(nil, nonce, cipherText[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func EncryptAESMust(aesKey, plainText []byte) []byte {
	cipherText, err := EncryptAES(aesKey, plainText)
	if err != nil {
		return plainText
	}
	return cipherText
}

func DecryptAESMust(aesKey, cipherText []byte) []byte {
	plainText, err := DecryptAES(aesKey, cipherText)
	if err != nil {
		return cipherText
	}
	return plainText
}
