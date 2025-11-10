package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"decryption-exercise/internals/aes/decrypt"
	"decryption-exercise/internals/jwt"
)

const (
	encryptedText = "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNMb2MsQkXm8kJDJuhcTBipXe"
	passphrase    = "codingexcercise"
)

func main() {
	// Initialize logger
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
