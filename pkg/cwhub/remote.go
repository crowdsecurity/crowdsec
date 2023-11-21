package cwhub

import (
	"fmt"
	"io"
	"net/http"
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
func (r *RemoteHubCfg) fetchIndex() ([]byte, error) {
	if r == nil {
		return nil, ErrNilRemoteHub
	}

	url, err := r.urlTo(r.IndexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build hub index request: %w", err)
	}

	resp, err := hubClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed http request for hub index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, IndexNotFoundError{url, r.Branch}
		}

		return nil, fmt.Errorf("bad http code %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request answer for hub index: %w", err)
	}

	return body, nil
}
