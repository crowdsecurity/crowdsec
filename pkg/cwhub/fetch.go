package cwhub

// Install, upgrade and remove items from the hub to the local configuration

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/downloader"

)

// FetchContentTo downloads the last version of the item's YAML file to the specified path.
func (i *Item) FetchContentTo(ctx context.Context, destPath string) (bool, string, error) {
	wantHash := i.latestHash()
	if wantHash == "" {
		return false, "", fmt.Errorf("%s: latest hash missing from index. The index file is invalid, please run 'cscli hub update' and try again", i.FQName())
	}

	// Use the embedded content if available
	if i.Content != "" {
		// the content was historically base64 encoded
		content, err := base64.StdEncoding.DecodeString(i.Content)
		if err != nil {
			content = []byte(i.Content)
		}

		dir := filepath.Dir(destPath)

		if err := os.MkdirAll(dir, 0o755); err != nil {
			return false, "", fmt.Errorf("while creating %s: %w", dir, err)
		}

		// check sha256
		hash := crypto.SHA256.New()
		if _, err := hash.Write(content); err != nil {
			return false, "", fmt.Errorf("while hashing %s: %w", i.Name, err)
		}

		gotHash := hex.EncodeToString(hash.Sum(nil))
		if gotHash != wantHash {
			return false, "", fmt.Errorf("hash mismatch: expected %s, got %s. The index file is invalid, please run 'cscli hub update' and try again", wantHash, gotHash)
		}

		if err := os.WriteFile(destPath, content, 0o600); err != nil {
			return false, "", fmt.Errorf("while writing %s: %w", destPath, err)
		}

		i.hub.logger.Debugf("Wrote %s content from .index.json to %s", i.Name, destPath)

		return true, fmt.Sprintf("(embedded in %s)", i.hub.local.HubIndexFile), nil
	}

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

	// TODO: recommend hub update if hash does not match

	downloaded, err := d.Download(ctx, url)
	if err != nil {
		return false, "", err
	}

	return downloaded, url, nil
}
