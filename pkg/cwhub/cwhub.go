package cwhub

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
)

// hubTransport wraps a Transport to set a custom User-Agent.
type hubTransport struct {
	http.RoundTripper
}

func (t *hubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", useragent.Default())
	return t.RoundTripper.RoundTrip(req)
}

// HubClient is the HTTP client used to communicate with the CrowdSec Hub.
var HubClient = &http.Client{
	Timeout:   120 * time.Second,
	Transport: &hubTransport{http.DefaultTransport},
}

// SafePath returns a joined path and ensures that it does not escape the base directory.
func SafePath(dir, filePath string) (string, error) {
	absBaseDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", err
	}

	absFilePath, err := filepath.Abs(filepath.Join(dir, filePath))
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(absFilePath, absBaseDir) {
		return "", fmt.Errorf("path %s escapes base directory %s", filePath, dir)
	}

	return absFilePath, nil
}
