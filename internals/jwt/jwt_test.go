package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCreate(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		secret    string
		wantErr   bool
		wantParts int
		verifySig bool
	}{
		{
			name:      "valid JWT creation with test payload",
			payload:   `{"decoded string":"test"}`,
			secret:    "codingexcercise",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
		{
			name:      "valid JWT with empty payload",
			payload:   `{}`,
			secret:    "codingexcercise",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
		{
			name:      "valid JWT with complex payload",
			payload:   `{"decoded string":"test","timestamp":1234567890}`,
			secret:    "codingexcercise",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
		{
			name:      "JWT with empty secret",
			payload:   `{"decoded string":"test"}`,
			secret:    "",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
		{
			name:      "JWT with different secret",
			payload:   `{"decoded string":"test"}`,
			secret:    "differentsecret",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
		{
			name:      "empty payload should fail",
			payload:   "",
			secret:    "codingexcercise",
			wantErr:   true,
			wantParts: 0,
			verifySig: false,
		},
		{
			name:      "very long payload should succeed",
			payload:   strings.Repeat(`{"data":"test"}`, 1000),
			secret:    "codingexcercise",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
		{
			name:      "payload with special characters should succeed",
			payload:   `{"data":"test with special chars: !@#$%^&*()"}`,
			secret:    "codingexcercise",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
		{
			name:      "payload with unicode characters should succeed",
			payload:   `{"data":"🚀 émoji"}`,
			secret:    "codingexcercise",
			wantErr:   false,
			wantParts: 3,
			verifySig: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt, err := Create(tt.payload, tt.secret)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Create() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if jwt == "" {
				t.Error("Create() returned empty JWT token")
				return
			}

			// Verify JWT structure (header.payload.signature)
			parts := strings.Split(jwt, ".")
			if len(parts) != tt.wantParts {
				t.Errorf("Create() JWT should have %d parts, got %d", tt.wantParts, len(parts))
			}

			// Verify signature if requested
			if tt.verifySig && len(parts) == 3 {
				message := parts[0] + "." + parts[1]
				mac := hmac.New(sha256.New, []byte(tt.secret))
				mac.Write([]byte(message))
				expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

				if parts[2] != expectedSignature {
					t.Error("Create() JWT signature verification failed")
				}
			}

			t.Logf("JWT token: %s", jwt)
		})
	}
}
