package cwhub

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/downloader"
)

// RemoteHubCfg is used to retrieve index and items from the remote hub.
type RemoteHubCfg struct {
	Branch           string
	URLTemplate      string
	IndexPath        string
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

// addURLParam adds a parameter with a value (ex. "with_content=true") to the URL if it's not already present.
func addURLParam(rawURL string, param string, value string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	query := parsedURL.Query()

	if _, exists := query[param]; !exists {
		query.Add(param, value)
	}

	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// fetchIndex downloads the index from the hub and returns the content.
func (r *RemoteHubCfg) fetchIndex(ctx context.Context, destPath string, withContent bool) (bool, error) {
	if r == nil {
		return false, ErrNilRemoteHub
	}

	url, err := r.urlTo(r.IndexPath)
	if err != nil {
		return false, fmt.Errorf("failed to build hub index request: %w", err)
	}

	if withContent {
		url, err = addURLParam(url, "with_content", "true")
		if err != nil {
			return false, fmt.Errorf("failed to add 'with_content' parameter to URL: %w", err)
		}
	}

	downloaded, err := downloader.
		New().
		WithHTTPClient(HubClient).
		ToFile(destPath).
		WithETagFn(downloader.SHA256).
		CompareContent().
		WithLogger(logrus.WithField("url", url)).
		BeforeRequest(func(_ *http.Request) {
			fmt.Println("Downloading "+destPath)
		}).
		Download(ctx, url)
	if err != nil {
		return false, err
	}

	return downloaded, nil
}
