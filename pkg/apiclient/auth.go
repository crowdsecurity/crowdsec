package apiclient

import (
	"errors"
	"net/http"
)

type APIKeyTransport struct {
	APIKey string

	// Transport is the underlying HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	Transport http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
func (t *APIKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.APIKey == "" {
		return nil, errors.New("t.APIKey is empty")
	}

	// We must make a copy of the Request so
	// that we don't modify the Request we were given. This is required by the
	// specification of http.RoundTripper.
	req = cloneRequest(req)
	req.Header.Add("X-Api-Key", t.APIKey)
	// Make the HTTP request.
	return t.transport().RoundTrip(req)
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

// cloneRequest returns a clone of the provided *http.Request. The clone is a
// shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
