package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Mode represents the encryption mode
type Mode string

const (
	// CBC - Cipher Block Chaining mode
	CBC Mode = "CBC"
	// CFB - Cipher Feedback mode
	CFB Mode = "CFB"
)

// Decrypt decrypts base64-encoded AES encrypted text
func Decrypt(encryptedBase64, passphrase string, mode Mode) (string, error) {
	// Decode base64 (and consider the need for adding padding)
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		// Consider the need for adding padding
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

	// Validate ciphertext length
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short: need at least %d bytes for IV", aes.BlockSize)
	}

	// Obtain key from passphrase using SHA256
	key := sha256.Sum256([]byte(passphrase))

	// Create cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	// Extract IV (first 16 bytes) and actual ciphertext
	iv := ciphertext[:aes.BlockSize]
	actualCiphertext := ciphertext[aes.BlockSize:]

	// Decrypt based on provided mode
	switch mode {
	case CBC:
		return decryptCBC(block, iv, actualCiphertext)
	case CFB:
		return decryptCFB(block, iv, actualCiphertext)
	default:
		return "", fmt.Errorf("unsupported mode: %s (supported: CBC, CFB)", mode)
	}
}

// decryptCBC decrypts using CBC mode
func decryptCBC(block cipher.Block, iv, ciphertext []byte) (string, error) {
	// Validate ciphertext is block-aligned
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length (%d) is not a multiple of block size (%d) for CBC mode", len(ciphertext), aes.BlockSize)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	copy(decrypted, ciphertext)
	mode.CryptBlocks(decrypted, decrypted)

	// Remove PKCS7 padding
	plaintext := removePKCS7Padding(decrypted)
	return string(plaintext), nil
}

// decryptCFB decrypts using CFB mode
func decryptCFB(block cipher.Block, iv, ciphertext []byte) (string, error) {
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	stream.XORKeyStream(decrypted, ciphertext)

	// Remove PKCS7 padding (normally, CFB doesn't require it, but we should handle it if present)
	plaintext := removePKCS7Padding(decrypted)
	return string(plaintext), nil
}

// removePKCS7Padding removes PKCS7 padding from decrypted data
func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	padding := int(data[len(data)-1])

	// Validate padding
	if padding == 0 || padding > len(data) || padding > aes.BlockSize {
		return data
	}

	// Verify all padding bytes are the same
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return data // Invalid padding, return as-is
		}
	}

	return data[:len(data)-padding]
}
