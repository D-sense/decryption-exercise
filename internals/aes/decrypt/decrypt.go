package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

// Mode represents the encryption mode
type Mode string

const (
	// CBC - Cipher Block Chaining mode
	CBC Mode = "CBC"
)

// Decrypt decrypts base64-encoded AES encrypted text using the specified mode
// Implements the team's specification exactly:
//
//	ciphertext = b64decode(ciphertext_b64)
//	salt = ciphertext[:16]
//	iv = ciphertext[16:32]
//	ct = ciphertext[32:]
//	key = PBKDF2(passphrase, salt, dkLen=32, count=100000)  // Uses SHA256 (Python default)
//	cipher = AES.new(key, AES.MODE_CBC, iv)
//
// Padding: PKCS7 (automatically handled by Python's AES.MODE_CBC)
func Decrypt(encryptedBase64, passphrase string, mode Mode) (string, error) {
	// Decode base64 (and consider the need for adding padding)
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
			return "", fmt.Errorf("base64 decode error: %v", err)
		}
	}

	// Validate minimum length
	if len(ciphertext) < 32+aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short: need at least %d bytes (salt+iv+block)", 32+aes.BlockSize)
	}

	salt := ciphertext[:16]
	iv := ciphertext[16:32]
	actualCiphertext := ciphertext[32:]

	key := pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher creation error: %v", err)
	}

	// Decrypt based on specified mode
	switch mode {
	case CBC:
		return decryptCBC(block, iv, actualCiphertext)
	default:
		return "", fmt.Errorf("unsupported mode: %s (supported: CBC)", mode)
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
