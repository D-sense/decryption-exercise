package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"lloyds-exercise/internals/aes/decrypt"
	"lloyds-exercise/internals/jwt"
	"log"
)

const (
	encryptedText = "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNMb2MsQkXm8kJDJuhcTBipXe"
	passphrase    = "codingexcercise"
)

func main() {
	// Step 1: Decrypt AES encoded text
	decrypted, err := decrypt.Decrypt(encryptedText, passphrase, decrypt.CBC)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	log.Printf("Decrypted text: %s", decrypted)

	// Step 2: Create JSON object
	jsonData := map[string]string{
		"decoded string": decrypted,
	}
	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		log.Fatalf("JSON marshaling failed: %v", err)
	}
	jsonString := string(jsonBytes)
	log.Printf("JSON object: %s", jsonString)

	// Step 3: Generate SHA256 hash
	hash := sha256.Sum256(jsonBytes)
	hashHex := fmt.Sprintf("%x", hash)
	log.Printf("SHA256 hash: %s", hashHex)

	// Step 3a: Create JWT using HMAC
	jwtToken, err := jwt.Create(jsonString, passphrase)
	if err != nil {
		log.Fatalf("JWT creation failed: %v", err)
	}

	log.Printf("JWT token: %s", jwtToken)
}
