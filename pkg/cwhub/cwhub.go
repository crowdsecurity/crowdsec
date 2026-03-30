package cwhub

import (
	"net/http"
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
	Timeout:   10 * time.Minute,
	Transport: &hubTransport{http.DefaultTransport},
}
