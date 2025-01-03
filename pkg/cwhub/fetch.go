package cwhub

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// writeEmbeddedContentTo writes the embedded content to the specified path and checks the hash.
// If the content is base64 encoded, it will be decoded before writing. Call this method only
// if item.Content if not empty.
func (i *Item) writeEmbeddedContentTo(destPath, wantHash string) error {
	if i.Content == "" {
		return fmt.Errorf("no embedded content for %s", i.Name)
	}

	content, err := base64.StdEncoding.DecodeString(i.Content)
	if err != nil {
		content = []byte(i.Content)
	}

	dir := filepath.Dir(destPath)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("while creating %s: %w", dir, err)
	}

	// check sha256
	hash := crypto.SHA256.New()
	if _, err := hash.Write(content); err != nil {
		return fmt.Errorf("while hashing %s: %w", i.Name, err)
	}

	gotHash := hex.EncodeToString(hash.Sum(nil))
	if gotHash != wantHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s. The index file is invalid, please run 'cscli hub update' and try again", wantHash, gotHash)
	}

	if err := os.WriteFile(destPath, content, 0o600); err != nil {
		return fmt.Errorf("while writing %s: %w", destPath, err)
	}

	return nil
}

// FetchContentTo writes the last version of the item's YAML file to the specified path.
// If the file is embedded in the index file, it will be written directly without downloads.
// Returns whether the file was downloaded (to inform if the security engine needs reloading)
// and the remote url for feedback purposes.
func (i *Item) FetchContentTo(ctx context.Context, contentProvider ContentProvider, destPath string) (bool, string, error) {
	wantHash := i.latestHash()
	if wantHash == "" {
		return false, "", fmt.Errorf("%s: latest hash missing from index. The index file is invalid, please run 'cscli hub update' and try again", i.FQName())
	}

	// Use the embedded content if available
	if i.Content != "" {
		if err := i.writeEmbeddedContentTo(destPath, wantHash); err != nil {
			return false, "", err
		}

		return true, fmt.Sprintf("(embedded in %s)", i.hub.local.HubIndexFile), nil
	}

	return contentProvider.FetchContent(ctx, i.RemotePath, destPath, wantHash, i.hub.logger)
}
