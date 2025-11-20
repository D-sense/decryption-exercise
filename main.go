package main

import (
	"crypto/sha256"
	"decryption-exercise/internals/aes/decrypt"
	"decryption-exercise/internals/jwt"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
)

const (
	encryptedText = "4Mjg0w+aI8ZkCOH+zH/mPNXkXxs93dzmER99a42bOP1MMRN7FNE3VgvLLQYD1/qNTEsxlTvgAiWMbT4G2IXzHYZynCHZciFdYP6ucbtlZt8="
	passphrase    = "codingexercise"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}
	defer logger.Sync()

	logger.Info("Starting decryption process...")

	// Step 1: Decrypt AES encoded text
	decrypted, err := decrypt.Decrypt(encryptedText, passphrase, decrypt.CBC)
	if err != nil {
		logger.Fatal("Decryption failed with both modes", zap.Error(err))
	}
	logger.Info("Decrypted text", zap.String("decrypted", decrypted))

	// Step 2: Create JSON object
	jsonData := map[string]string{
		"decoded string": decrypted,
	}
	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		logger.Fatal("JSON marshaling failed", zap.Error(err))
	}
	jsonString := string(jsonBytes)
	logger.Info("JSON object", zap.String("json", jsonString))

	// Step 3: Generate SHA256 hash
	hash := sha256.Sum256(jsonBytes)
	hashHex := fmt.Sprintf("%x", hash)
	logger.Info("SHA256 hash", zap.String("hash", hashHex))

	// Step 3a: Create JWT using HMAC
	jwtToken, err := jwt.Create(jsonString, passphrase)
	if err != nil {
		logger.Fatal("JWT creation failed", zap.Error(err))
	}

	logger.Info("JWT token", zap.String("token", jwtToken))
}
