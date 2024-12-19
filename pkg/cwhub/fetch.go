package cwhub

// Install, upgrade and remove items from the hub to the local configuration

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/downloader"

)


// writeEmbeddedContentTo writes the embedded content to the specified path and checks the hash.
// If the content is base64 encoded, it will be decoded before writing. Check for item.Content
// before calling this method.
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

// writeRemoteContentTo downloads the content to the specified path and checks the hash.
func (i *Item) writeRemoteContentTo(ctx context.Context, destPath, wantHash string) (bool, string, error) {
	url, err := i.hub.remote.urlTo(i.RemotePath)
	if err != nil {
		return false, "", fmt.Errorf("failed to build request: %w", err)
	}

	d := downloader.
		New().
		WithHTTPClient(HubClient).
		ToFile(destPath).
		WithETagFn(downloader.SHA256).
		WithMakeDirs(true).
		WithLogger(logrus.WithField("url", url)).
		CompareContent().
		VerifyHash("sha256", wantHash)

	hasherr := downloader.HashMismatchError{}

	downloaded, err := d.Download(ctx, url)

	switch {
	case errors.As(err, &hasherr):
		i.hub.logger.Warnf("%s. The index file is outdated, please run 'cscli hub update' and try again", err.Error())
	case err != nil:
		return false, "", err
	}

	return downloaded, url, nil
}

// FetchContentTo writes the last version of the item's YAML file to the specified path.
// Returns whether the file was downloaded, and the remote url for feedback purposes.
func (i *Item) FetchContentTo(ctx context.Context, destPath string) (bool, string, error) {
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

	return i.writeRemoteContentTo(ctx, destPath, wantHash)
}
