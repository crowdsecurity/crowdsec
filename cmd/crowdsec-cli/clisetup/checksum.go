package clisetup

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const minChecksumLength = 16

var (
	ErrChecksumMismatch = errors.New("checksum mismatch")
	ErrChecksumNotFound = errors.New("checksum comment not found")
	ErrChecksumTooShort = fmt.Errorf("checksum too short, must be at least %d characters", minChecksumLength)
)

// VerifyChecksum reads a YAML file with a head comment like `# cscli-checksum: abcdef123456`
// and verifies that the hash of the remainder of the file matches the checksum.
// It returns nil if the checksum is valid, or an error otherwise.
func VerifyChecksum(r io.Reader) error {
	scanner := bufio.NewScanner(r)

	var (
		foundChecksum string
		content       bytes.Buffer
	)

	for scanner.Scan() {
		line := scanner.Text()

		// stop skipping if we reach anything that's not a comment or blank line
		if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
			// write this line and the rest to the buffer
			content.WriteString(line)
			content.WriteByte('\n')

			break
		}

		if val, ok := strings.CutPrefix(line, "# cscli-checksum:"); ok {
			foundChecksum = strings.TrimSpace(val)
		}
	}

	// append remaining lines

	for scanner.Scan() {
		content.WriteString(scanner.Text())
		content.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if foundChecksum == "" {
		return ErrChecksumNotFound
	}

	// compute full SHA256 and compare truncated value,
	// good enough for our use case

	full := sha256.Sum256(content.Bytes())
	actual := hex.EncodeToString(full[:])

	if len(foundChecksum) < 16 {
		return ErrChecksumTooShort
	}

	if !strings.HasPrefix(actual, foundChecksum) {
		return ErrChecksumMismatch
	}

	return nil
}
