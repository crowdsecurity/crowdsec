package apiclient

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"

	log "github.com/sirupsen/logrus"
)

type APIKeyTransport struct {
	APIKey string
	// Transport is the underlying HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	Transport     http.RoundTripper
	URL           *url.URL
	VersionPrefix string
	UserAgent     string
}

// RoundTrip implements the RoundTripper interface.
func (t *APIKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.APIKey == "" {
		return nil, errors.New("APIKey is empty")
	}

	// We must make a copy of the Request so
	// that we don't modify the Request we were given. This is required by the
	// specification of http.RoundTripper.
	req = cloneRequest(req)
	req.Header.Add("X-Api-Key", t.APIKey)

	if t.UserAgent != "" {
		req.Header.Add("User-Agent", t.UserAgent)
	}

	log.Debugf("req-api: %s %s", req.Method, req.URL.String())

	if log.IsLevelEnabled(log.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("auth-api request: %s", string(dump))
	}

	// Make the HTTP request.
	resp, err := t.transport().RoundTrip(req)
	if err != nil {
		log.Errorf("auth-api: auth with api key failed return nil response, error: %s", err)

		return resp, err
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Tracef("auth-api response: %s", string(dump))
	}

	log.Debugf("resp-api: http %d", resp.StatusCode)

	return resp, err
}

func (t *APIKeyTransport) Client() *http.Client {
	return &http.Client{Transport: t}
}

func (t *APIKeyTransport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}

	return http.DefaultTransport
}
