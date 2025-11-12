package decrypt

import (
	"encoding/base64"
	"testing"
)

func TestDecrypt(t *testing.T) {
	var tests []struct {
		name          string
		encryptedText string
		passphrase    string
		mode          Mode
		wantErr       bool
		wantEmpty     bool
	}

	// This helper builds b64 string: [salt(16)][iv(16)][ct]
	buildB64 := func(salt, iv, ct []byte) string {
		b := make([]byte, 0, len(salt)+len(iv)+len(ct))
		b = append(b, salt...)
		b = append(b, iv...)
		b = append(b, ct...)
		return base64.StdEncoding.EncodeToString(b)
	}

	salt := []byte("1234567890abcdef")
	iv := []byte("abcdef1234567890")
	ctBlockAligned := []byte("0123456789abcdef")
	ctNotAligned := []byte("0123456789abcde")

	tests = append(tests,
		struct {
			name          string
			encryptedText string
			passphrase    string
			mode          Mode
			wantErr       bool
			wantEmpty     bool
		}{
			name:          "CBC mode with block-aligned data",
			encryptedText: buildB64(salt, iv, ctBlockAligned),
			passphrase:    "test",
			mode:          CBC,
			wantErr:       false,
			wantEmpty:     false,
		},
	)

	tests = append(tests,
		struct {
			name          string
			encryptedText string
			passphrase    string
			mode          Mode
			wantErr       bool
			wantEmpty     bool
		}{
			name:          "CBC mode with non-block-aligned data should fail",
			encryptedText: buildB64(salt, iv, ctNotAligned),
			passphrase:    "test",
			mode:          CBC,
			wantErr:       true,
			wantEmpty:     true,
		},
	)

	tests = append(tests,
		struct {
			name          string
			encryptedText string
			passphrase    string
			mode          Mode
			wantErr       bool
			wantEmpty     bool
		}{
			name:          "invalid mode",
			encryptedText: buildB64(salt, iv, ctBlockAligned),
			passphrase:    "test",
			mode:          Mode("INVALID"),
			wantErr:       true,
			wantEmpty:     true,
		},
	)

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
