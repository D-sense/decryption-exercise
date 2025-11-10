package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Create creates JWT token using HMAC-SHA256
func Create(payload, secret string) (string, error) {
	if payload == "" {
		return "", fmt.Errorf("payload cannot be empty")
	}

	// JWT header
	header := `{"alg":"HS256","typ":"JWT"}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))

	// JWT payload
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	// Creates signature
	message := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Combine message and signature to form JWT
	jwt := message + "." + signature
	return jwt, nil
}
