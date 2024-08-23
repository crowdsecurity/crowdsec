package cwhub

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/downloader"
)

// RemoteHubCfg is used to retrieve index and items from the remote hub.
type RemoteHubCfg struct {
	Branch      string
	URLTemplate string
	IndexPath   string
}

// urlTo builds the URL to download a file from the remote hub.
func (r *RemoteHubCfg) urlTo(remotePath string) (string, error) {
	if r == nil {
		return "", ErrNilRemoteHub
	}

	// the template must contain two string placeholders
	if fmt.Sprintf(r.URLTemplate, "%s", "%s") != r.URLTemplate {
		return "", fmt.Errorf("invalid URL template '%s'", r.URLTemplate)
	}

	return fmt.Sprintf(r.URLTemplate, r.Branch, remotePath), nil
}

// fetchIndex downloads the index from the hub and returns the content.
func (r *RemoteHubCfg) fetchIndex(ctx context.Context, destPath string) (bool, error) {
	if r == nil {
		return false, ErrNilRemoteHub
	}

	url, err := r.urlTo(r.IndexPath)
	if err != nil {
		return false, fmt.Errorf("failed to build hub index request: %w", err)
	}

	downloaded, err := downloader.
		New().
		WithHTTPClient(hubClient).
		ToFile(destPath).
		WithETagFn(downloader.SHA256).
		CompareContent().
		WithLogger(logrus.WithField("url", url)).
		Download(ctx, url)
	if err != nil {
		return false, err
	}

	return downloaded, nil
}
