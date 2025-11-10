package decrypt

import (
	"testing"
)

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name          string
		encryptedText string
		passphrase    string
		mode          Mode
		wantErr       bool
		wantEmpty     bool
	}{
		{
			name:          "CFB mode with exercise passphrase",
			encryptedText: "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNMb2MsQkXm8kJDJuhcTBipXe",
			passphrase:    "codingexcercise",
			mode:          CFB,
			wantErr:       false,
			wantEmpty:     false,
		},
		{
			name:          "CBC mode with block-aligned data",
			encryptedText: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			passphrase:    "test",
			mode:          CBC,
			wantErr:       false, // Here, CBC will succeed with block-aligned data (even if result is garbage)
			wantEmpty:     false,
		},
		{
			name:          "CBC mode with non-block-aligned data should fail",
			encryptedText: "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNM",
			passphrase:    "codingexcercise",
			mode:          CBC,
			wantErr:       true,
			wantEmpty:     true,
		},
		{
			name:          "CFB mode with invalid passphrase",
			encryptedText: "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNMb2MsQkXm8kJDJuhcTBipXe",
			passphrase:    "wrongpassphrase",
			mode:          CFB,
			wantErr:       false,
			wantEmpty:     false,
		},
		{
			name:          "empty encrypted text",
			encryptedText: "",
			passphrase:    "codingexcercise",
			mode:          CFB,
			wantErr:       true,
			wantEmpty:     true,
		},
		{
			name:          "invalid mode",
			encryptedText: "gAdpIUlI6vo3DKj/1SHc7rXKXgRuh2ej8iybshbWza+sPQu79Au6GVvyubwzI3gccKUE9n1VuCYG930FpXeMZn85ZxOgQuHdyCb1Dx4PNMb2MsQkXm8kJDJuhcTBipXe",
			passphrase:    "codingexcercise",
			mode:          Mode("INVALID"),
			wantErr:       true,
			wantEmpty:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypted, err := Decrypt(tt.encryptedText, tt.passphrase, tt.mode)

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
