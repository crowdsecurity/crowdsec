package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

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
			return fmt.Errorf("can't update scenario list: %w", err)
		}

		log.Debugf("scenarios list updated for '%s'", *t.MachineID)
	}

	auth := models.WatcherAuthRequest{
		MachineID: t.MachineID,
		Password:  t.Password,
		Scenarios: t.Scenarios,
	}

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

	var response models.WatcherAuthResponse

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

func (t *JWTTransport) needsTokenRefresh() bool {
	return t.Token == "" || t.Expiration.Add(-time.Minute).Before(time.Now().UTC())
}

// prepareRequest returns a copy of the  request with the necessary authentication headers.
func (t *JWTTransport) prepareRequest(req *http.Request) (*http.Request, error) {
	req = cloneRequest(req)

	// In a few occasions several goroutines will execute refreshJwtToken concurrently which is useless
	// and will cause overload on CAPI. We use a mutex to avoid this.
	t.refreshTokenMutex.Lock()
	defer t.refreshTokenMutex.Unlock()

	// We bypass the refresh if we are requesting the login endpoint, as it does not require a token,
	// and it leads to do 2 requests instead of one (refresh + actual login request).
	if req.URL.Path != "/"+t.VersionPrefix+"/watchers/login" && t.needsTokenRefresh() {
		if err := t.refreshJwtToken(); err != nil {
			return nil, err
		}
	}

	if t.UserAgent != "" {
		req.Header.Add("User-Agent", t.UserAgent)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t.Token))

	return req, nil
}

// RoundTrip implements the RoundTripper interface.
func (t *JWTTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req, err := t.prepareRequest(req)
	if err != nil {
		return nil, err
	}

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
		// we had an error (network error for example, or 401 because token is refused), reset the token?
		t.ResetToken()

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

// transport() returns a round tripper that retries once when the status is unauthorized,
// and 5 times when the infrastructure is overloaded.
func (t *JWTTransport) transport() http.RoundTripper {
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

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
