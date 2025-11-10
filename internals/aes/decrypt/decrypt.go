package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Decrypt decrypts base64-encoded AES encrypted text
func Decrypt(encryptedBase64, passphrase string) (string, error) {
	// Decode base64 - we are trying with padding, if needed.
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		switch len(encryptedBase64) % 4 {
		case 2:
			encryptedBase64 += "=="
		case 3:
			encryptedBase64 += "="
		}
		ciphertext, err = base64.StdEncoding.DecodeString(encryptedBase64)
		if err != nil {
			return "", fmt.Errorf("error decoding base64: %v", err)
		}
	}

	// Obtain key from passphrase using SHA256
	key := sha256.Sum256([]byte(passphrase))

	// Create cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	// Try CFB mode with IV prepended (common simple format)
	// CFB doesn't require ciphertext to be block-aligned
	var iv []byte
	var actualCiphertext []byte
	if len(ciphertext) >= aes.BlockSize {
		iv = ciphertext[:aes.BlockSize]
		actualCiphertext = make([]byte, len(ciphertext)-aes.BlockSize)
		copy(actualCiphertext, ciphertext[aes.BlockSize:])
	} else {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Use CFB decrypter (works with any ciphertext length)
	// Understandably, this method is deprecated in favor of authenticated encryption modes (e.g., GCM).
	// I use it here for compatibility with existing CFB-encrypted data.
	// For new encryption, I would consider using authenticated modes like AES-GCM.
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(actualCiphertext))
	stream.XORKeyStream(decrypted, actualCiphertext)

	// Remove PKCS7 padding
	plaintext := removePKCS7Padding(decrypted)
	return string(plaintext), nil
}

// removePKCS7Padding removes PKCS7 padding
func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return data
	}
	return data[:len(data)-padding]
}
