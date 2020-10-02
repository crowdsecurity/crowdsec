package apiclient

import (
	"bytes"
	"encoding/json"
	"time"

	//"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	//"google.golang.org/appengine/log"
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
	log.Debugf("req-api: %s %s", req.Method, req.URL.String())
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("req-api: %s", string(dump))
	}
	// Make the HTTP request.
	resp, err := t.transport().RoundTrip(req)
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Tracef("resp-api: %s", string(dump))
	}

	log.Debugf("resp-api: %d", resp.StatusCode)

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

type JWTTransport struct {
	MachineID  *string
	Password   *strfmt.Password
	token      string
	Expiration time.Time
	Scenarios  []string
	// Transport is the underlying HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	Transport http.RoundTripper
}

func (t *JWTTransport) refreshJwtToken() error {

	var auth = models.WatcherAuthRequest{
		MachineID: t.MachineID,
		Password:  t.Password,
		Scenarios: t.Scenarios,
	}

	var response models.WatcherAuthResponse

	/*
		we don't use the main client, so let's build the body
	*/
	var buf io.ReadWriter
	buf = &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(auth)
	if err != nil {
		return errors.Wrap(err, "could not encode jwt auth body")
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%swatchers/login", BaseURL), buf)
	if err != nil {
		return errors.Wrap(err, "could not create request")
	}
	req.Header.Add("Content-Type", "application/json")
	client := &http.Client{}
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("req-jwt(auth): %s", string(dump))
	}

	log.Debugf("req-jwt(auth): %s %s", req.Method, req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "could not get jwt token")
	}
	log.Debugf("resp-jwt(auth): %d", resp.StatusCode)

	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Tracef("resp-jwt: %s", string(dump))
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received response status %q when fetching %v", resp.Status, req.URL)
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return errors.Wrap(err, "unable to decode response")
	}
	if err := t.Expiration.UnmarshalText([]byte(response.Expire)); err != nil {
		return errors.Wrap(err, "unable to parse jwt expiration")
	}
	t.token = response.Token

	log.Debugf("token %s will expire on %s", t.token, t.Expiration.String())
	return nil
}

// RoundTrip implements the RoundTripper interface.
func (t *JWTTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token == "" || t.Expiration.Add(-time.Minute).Before(time.Now()) {
		if err := t.refreshJwtToken(); err != nil {
			return nil, err
		}
	}

	// We must make a copy of the Request so
	// that we don't modify the Request we were given. This is required by the
	// specification of http.RoundTripper.
	req = cloneRequest(req)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t.token))
	log.Debugf("req-jwt: %s %s", req.Method, req.URL.String())
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("req-jwt: %s", string(dump))
	}
	// Make the HTTP request.
	resp, err := t.transport().RoundTrip(req)
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Tracef("resp-jwt: %s", string(dump))
	}
	log.Debugf("resp-jwt: %d", resp.StatusCode)

	return resp, err
}

func (t *JWTTransport) Client() *http.Client {
	return &http.Client{Transport: t}
}

func (t *JWTTransport) transport() http.RoundTripper {
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
