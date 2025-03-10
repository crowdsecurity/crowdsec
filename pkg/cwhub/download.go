package cwhub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/downloader"
)

// no need to import the lib package to use this
type NotFoundError = downloader.NotFoundError

// Downloader is used to retrieve index and items from a remote hub, with cache control.
type Downloader struct {
	Branch      string
	URLTemplate string
}

// IndexProvider retrieves and writes .index.json
type IndexProvider interface {
	FetchIndex(ctx context.Context, indexFile string, withContent bool, logger *logrus.Logger) (bool, error)
}

// ContentProvider retrieves and writes the YAML files with the item content.
type ContentProvider interface {
	FetchContent(ctx context.Context, remotePath, destPath, wantHash string, logger *logrus.Logger) (bool, string, error)
}

// urlTo builds the URL to download a file from the remote hub.
func (d *Downloader) urlTo(remotePath string) (string, error) {
	// the template must contain two string placeholders
	if fmt.Sprintf(d.URLTemplate, "%s", "%s") != d.URLTemplate {
		return "", fmt.Errorf("invalid URL template '%s'", d.URLTemplate)
	}

	return fmt.Sprintf(d.URLTemplate, d.Branch, remotePath), nil
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

// FetchIndex downloads the index from the hub and writes it to the filesystem.
// It uses a temporary file to avoid partial downloads, and won't overwrite the original
// if it has not changed.
// Return true if the file has been updated, false if already up to date.
func (d *Downloader) FetchIndex(ctx context.Context, destPath string, withContent bool, logger *logrus.Logger) (bool, error) {
	url, err := d.urlTo(".index.json")
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
		WithLogger(logger.WithField("url", url)).
		BeforeRequest(func(_ *http.Request) {
			fmt.Println("Downloading " + destPath)
		}).
		Download(ctx, url)
	if err != nil {
		return false, err
	}

	return downloaded, nil
}

// FetchContent downloads the content to the specified path, through a temporary file
// to avoid partial downloads.
// If the hash does not match, it will not overwrite and log a warning.
func (d *Downloader) FetchContent(ctx context.Context, remotePath, destPath, wantHash string, logger *logrus.Logger) (bool, string, error) {
	url, err := d.urlTo(remotePath)
	if err != nil {
		return false, "", fmt.Errorf("failed to build request: %w", err)
	}

	downloaded, err := downloader.
		New().
		WithHTTPClient(HubClient).
		ToFile(destPath).
		WithETagFn(downloader.SHA256).
		WithMakeDirs(true).
		WithLogger(logger.WithField("url", url)).
		CompareContent().
		VerifyHash("sha256", wantHash).
		Download(ctx, url)

	var hasherr downloader.HashMismatchError

	switch {
	case errors.As(err, &hasherr):
		logger.Warnf("%s. The index file is outdated, please run 'cscli hub update' and try again", err.Error())
	case err != nil:
		return false, "", err
	}

	return downloaded, url, nil
}
