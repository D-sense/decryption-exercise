package decrypt

import (
	"testing"
)

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name          string
		encryptedText string
		passphrase    string
		wantErr       bool
		wantEmpty     bool
	}{
		{
			name:          "valid decryption with exercise passphrase",
			encryptedText: "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNM",
			passphrase:    "codingexcercise",
			wantErr:       false,
			wantEmpty:     false,
		},
		{
			name:          "invalid passphrase",
			encryptedText: "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNM",
			passphrase:    "wrongpassphrase",
			wantErr:       false, // Decryption will succeed of course, but produce garbage
			wantEmpty:     false,
		},
		{
			name:          "empty encrypted text",
			encryptedText: "",
			passphrase:    "codingexcercise",
			wantErr:       true,
			wantEmpty:     true,
		},
		{
			name:          "empty passphrase",
			encryptedText: "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNM",
			passphrase:    "",
			wantErr:       false,
			wantEmpty:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypted, err := Decrypt(tt.encryptedText, tt.passphrase)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Decrypt() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantEmpty && decrypted != "" {
				t.Errorf("Decrypt() expected empty result, got %q", decrypted)
			}

			if !tt.wantEmpty && decrypted == "" {
				t.Errorf("Decrypt() expected non-empty result, got empty string")
			}

			t.Logf("Decrypted text: %s", decrypted)
		})
	}
}
