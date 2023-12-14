package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/models"
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

type retryRoundTripper struct {
	next             http.RoundTripper
	maxAttempts      int
	retryStatusCodes []int
	withBackOff      bool
	onBeforeRequest  func(attempt int)
}

func (r retryRoundTripper) ShouldRetry(statusCode int) bool {
	for _, code := range r.retryStatusCodes {
		if code == statusCode {
			return true
		}
	}

	return false
}

func (r retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)

	backoff := 0
	maxAttempts := r.maxAttempts

	if fflag.DisableHttpRetryBackoff.IsEnabled() {
		maxAttempts = 1
	}

	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			if r.withBackOff {
				backoff += 10 + rand.Intn(20)
			}

			log.Infof("retrying in %d seconds (attempt %d of %d)", backoff, i+1, r.maxAttempts)
			select {
			case <-req.Context().Done():
				return resp, req.Context().Err()
			case <-time.After(time.Duration(backoff) * time.Second):
			}
		}

		if r.onBeforeRequest != nil {
			r.onBeforeRequest(i)
		}

		clonedReq := cloneRequest(req)
		resp, err = r.next.RoundTrip(clonedReq)

		if err != nil {
			left := maxAttempts - i - 1
			if left > 0 {
				log.Errorf("error while performing request: %s; %d retries left", err, left)
			}

			continue
		}

		if !r.ShouldRetry(resp.StatusCode) {
			return resp, nil
		}
	}

	return resp, err
}

type JWTTransport struct {
	MachineID     *string
	Password      *strfmt.Password
	Token         string
	Expiration    time.Time
	Scenarios     []string
	URL           *url.URL
	VersionPrefix string
	UserAgent     string
	// Transport is the underlying HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	Transport         http.RoundTripper
	UpdateScenario    func() ([]string, error)
	refreshTokenMutex sync.Mutex
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
		return fmt.Errorf("could not encode jwt auth body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s/watchers/login", t.URL, t.VersionPrefix), buf)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Transport: &retryRoundTripper{
			next:             http.DefaultTransport,
			maxAttempts:      5,
			withBackOff:      true,
			retryStatusCodes: []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusInternalServerError},
		},
	}

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
		return fmt.Errorf("could not get jwt token: %w", err)
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
		return fmt.Errorf("unable to decode response: %w", err)
	}

	if err := t.Expiration.UnmarshalText([]byte(response.Expire)); err != nil {
		return fmt.Errorf("unable to parse jwt expiration: %w", err)
	}

	t.Token = response.Token

	log.Debugf("token %s will expire on %s", t.Token, t.Expiration.String())

	return nil
}

// RoundTrip implements the RoundTripper interface.
func (t *JWTTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// in a few occasions several goroutines will execute refreshJwtToken concurrently which is useless and will cause overload on CAPI
	// we use a mutex to avoid this
	//We also bypass the refresh if we are requesting the login endpoint, as it does not require a token, and it leads to do 2 requests instead of one (refresh + actual login request)
	t.refreshTokenMutex.Lock()
	if req.URL.Path != "/"+t.VersionPrefix+"/watchers/login" && (t.Token == "" || t.Expiration.Add(-time.Minute).Before(time.Now().UTC())) {
		if err := t.refreshJwtToken(); err != nil {
			t.refreshTokenMutex.Unlock()
			return nil, err
		}
	}
	t.refreshTokenMutex.Unlock()

	if t.UserAgent != "" {
		req.Header.Add("User-Agent", t.UserAgent)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t.Token))

	if log.GetLevel() >= log.TraceLevel {
		//requestToDump := cloneRequest(req)
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("req-jwt: %s", string(dump))
	}

	// Make the HTTP request.
	resp, err := t.transport().RoundTrip(req)
	if log.GetLevel() >= log.TraceLevel {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Tracef("resp-jwt: %s (err:%v)", string(dump), err)
	}

	if err != nil {
		/*we had an error (network error for example, or 401 because token is refused), reset the token ?*/
		t.Token = ""
		return resp, fmt.Errorf("performing jwt auth: %w", err)
	}

	if resp != nil {
		log.Debugf("resp-jwt: %d", resp.StatusCode)
	}

	return resp, nil
}

func (t *JWTTransport) Client() *http.Client {
	return &http.Client{Transport: t}
}

func (t *JWTTransport) ResetToken() {
	log.Debug("resetting jwt token")
	t.refreshTokenMutex.Lock()
	t.Token = ""
	t.refreshTokenMutex.Unlock()
}

func (t *JWTTransport) transport() http.RoundTripper {
	var transport http.RoundTripper
	if t.Transport != nil {
		transport = t.Transport
	} else {
		transport = http.DefaultTransport
	}
	// a round tripper that retries once when the status is unauthorized and 5 times when infrastructure is overloaded
	return &retryRoundTripper{
		next: &retryRoundTripper{
			next:             transport,
			maxAttempts:      5,
			withBackOff:      true,
			retryStatusCodes: []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout},
		},
		maxAttempts:      2,
		withBackOff:      false,
		retryStatusCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
		onBeforeRequest: func(attempt int) {
			// reset the token only in the second attempt as this is when we know we had a 401 or 403
			// the second attempt is supposed to refresh the token
			if attempt > 0 {
				t.ResetToken()
			}
		},
	}
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

	if r.Body != nil {
		var b bytes.Buffer

		b.ReadFrom(r.Body)

		r.Body = io.NopCloser(&b)
		r2.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
	}

	return r2
}
