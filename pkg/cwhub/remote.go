package cwhub

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
)

// RemoteHubCfg contains where to find the remote hub, which branch etc.
type RemoteHubCfg struct {
	Branch      string
	URLTemplate string
	IndexPath   string
}

func (r *RemoteHubCfg) urlTo(remotePath string) (string, error) {
	if r == nil {
		return "", ErrNilRemoteHub
	}

	if fmt.Sprintf(r.URLTemplate, "%s", "%s") != r.URLTemplate {
		return "", fmt.Errorf("invalid URL template '%s'", r.URLTemplate)
	}

	return fmt.Sprintf(r.URLTemplate, r.Branch, remotePath), nil
}

// downloadIndex downloads the latest version of the index
func (r *RemoteHubCfg) downloadIndex(localPath string) error {
	if r == nil {
		return ErrNilRemoteHub
	}

	url, err := r.urlTo(r.IndexPath)
	if err != nil {
		return fmt.Errorf("failed to build hub index request: %w", err)
	}

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed http request for hub index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return IndexNotFoundError{url, r.Branch}
		}

		return fmt.Errorf("bad http code %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read request answer for hub index: %w", err)
	}

	oldContent, err := os.ReadFile(localPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warningf("failed to read hub index: %s", err)
		}
	} else if bytes.Equal(body, oldContent) {
		log.Info("hub index is up to date")
		return nil
	}

	file, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)

	if err != nil {
		return fmt.Errorf("while opening hub index file: %w", err)
	}
	defer file.Close()

	wsize, err := file.Write(body)
	if err != nil {
		return fmt.Errorf("while writing hub index file: %w", err)
	}

	log.Infof("Wrote index to %s, %d bytes", localPath, wsize)

	return nil
}
