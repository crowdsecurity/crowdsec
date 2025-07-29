package clisetup

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyChecksum(t *testing.T) {
	body := `foo: bar
baz: qux
`

	fullHash := sha256.Sum256([]byte(body))
	fullChecksum := hex.EncodeToString(fullHash[:])

	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "no checksum present",
			input:   body,
			wantErr: ErrChecksumNotFound,
		},
		{
			name:  "full checksum match",
			input: "# cscli-checksum: " + fullChecksum + "\n" + body,
		},
		{
			name:  "checksum with comment before and after",
			input: "# comment 1\n# cscli-checksum: " + fullChecksum + "\n# comment 2\n" + body,
		},
		{
			name:    "too short checksum (8 chars)",
			input:   "# cscli-checksum: " + fullChecksum[:8] + "\n" + body,
			wantErr: ErrChecksumTooShort,
		},
		{
			name:  "truncated checksum (16 chars, valid)",
			input: "# cscli-checksum: " + fullChecksum[:16] + "\n" + body,
		},
		{
			name:    "wrong checksum",
			input:   "# cscli-checksum: 1234567890123456\n" + body,
			wantErr: ErrChecksumMismatch,
		},
		{
			name:    "modified content",
			input:   "# cscli-checksum: " + fullChecksum[:16] + "\n" + body + "2",
			wantErr: ErrChecksumMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyChecksum(strings.NewReader(tt.input))
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
