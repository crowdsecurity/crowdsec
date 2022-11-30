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
	"net/url"

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
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("auth-api request: %s", string(dump))
	}
	// Make the HTTP request.
	resp, err := t.transport().RoundTrip(req)
	if err != nil {
		log.Errorf("auth-api: auth with api key failed return nil response, error: %s", err)
		return resp, err
	}
	if log.GetLevel() >= log.TraceLevel {
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

type JWTTransport struct {
	MachineID     *string
	Password      *strfmt.Password
	token         string
	Expiration    time.Time
	Scenarios     []string
	URL           *url.URL
	VersionPrefix string
	UserAgent     string
	// Transport is the underlying HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	Transport      http.RoundTripper
	UpdateScenario func() ([]string, error)
}

func (t *JWTTransport) refreshJwtToken() error {
	var err error
	if t.UpdateScenario != nil {
		t.Scenarios, err = t.UpdateScenario()
		if err != nil {
			return fmt.Errorf("can't update scenario list: %s", err)
		}
		log.Debugf("scenarios list updated for '%s'", *t.MachineID)
	}

	var auth = models.WatcherAuthRequest{
		MachineID: t.MachineID,
		Password:  t.Password,
		Scenarios: t.Scenarios,
	}

	var response models.WatcherAuthResponse

	/*
		we don't use the main client, so let's build the body
	*/
	var buf io.ReadWriter = &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err = enc.Encode(auth)
	if err != nil {
		return errors.Wrap(err, "could not encode jwt auth body")
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s/watchers/login", t.URL, t.VersionPrefix), buf)
	if err != nil {
		return errors.Wrap(err, "could not create request")
	}
	req.Header.Add("Content-Type", "application/json")
	client := &http.Client{}
	if t.UserAgent != "" {
		req.Header.Add("User-Agent", t.UserAgent)
	}
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("auth-jwt request: %s", string(dump))
	}

	log.Debugf("auth-jwt(auth): %s %s", req.Method, req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "could not get jwt token")
	}
	log.Debugf("auth-jwt : http %d", resp.StatusCode)

	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Tracef("auth-jwt response: %s", string(dump))
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Debugf("received response status %q when fetching %v", resp.Status, req.URL)
		err = CheckResponse(resp)
		if err != nil {
			return err
		}
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
	if t.token == "" || t.Expiration.Add(-time.Minute).Before(time.Now().UTC()) {
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
	if t.UserAgent != "" {
		req.Header.Add("User-Agent", t.UserAgent)
	}
	// Make the HTTP request.
	resp, err := t.transport().RoundTrip(req)
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Tracef("resp-jwt: %s (err:%v)", string(dump), err)
	}
	if err != nil || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		/*we had an error (network error for example, or 401 because token is refused), reset the token ?*/
		t.token = ""
		return resp, errors.Wrapf(err, "performing jwt auth")
	}
	log.Debugf("resp-jwt: %d", resp.StatusCode)
	return resp, nil
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
