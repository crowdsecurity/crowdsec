package apiclient

import (
	"bytes"
	"context"
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
	RetryConfig   *RetryConfig
	// Transport is the underlying HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	Transport        http.RoundTripper
	UpdateScenario   func(context.Context) ([]string, error)
	TokenRefreshChan chan struct{} // will write to this channel when the token is refreshed

	refreshTokenMutex sync.Mutex
	TokenSave         TokenSave
}

func (t *JWTTransport) refreshJwtToken(ctx context.Context) error {
	var err error

	log.Debugf("refreshing jwt token for '%s'", *t.MachineID)

	if t.UpdateScenario != nil {
		t.Scenarios, err = t.UpdateScenario(ctx)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s%s/watchers/login", t.URL, t.VersionPrefix), buf)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")

	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	client := &http.Client{
		Transport: &retryRoundTripper{
			next:             transport,
			maxAttempts:      5,
			withBackOff:      true,
			retryStatusCodes: []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusInternalServerError},
		},
	}

	if t.UserAgent != "" {
		req.Header.Add("User-Agent", t.UserAgent)
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, true)
		log.Tracef("auth-jwt request: %s", string(dump))
	}

	log.Debugf("auth-jwt(auth): %s %s", req.Method, req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not get jwt token: %w", err)
	}

	log.Debugf("auth-jwt : http %d", resp.StatusCode)

	if log.IsLevelEnabled(log.TraceLevel) {
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

	if t.TokenSave != nil {
		err = t.TokenSave(ctx, TokenDBField, t.Token)
		if err != nil {
			log.Errorf("unable to save token: %s", err)
		}
	}

	log.Debugf("token %s will expire on %s", t.Token, t.Expiration.String())

	select {
	case t.TokenRefreshChan <- struct{}{}:
	default:
		// Do not block if no one is waiting for the token refresh (ie, PAPI fully disabled)
	}

	return nil
}

func (t *JWTTransport) needsTokenRefresh() bool {
	return t.Token == "" || t.Expiration.Add(-time.Minute).Before(time.Now().UTC())
}

// prepareRequest returns a copy of the  request with the necessary authentication headers.
func (t *JWTTransport) prepareRequest(req *http.Request) (*http.Request, error) {
	// In a few occasions several goroutines will execute refreshJwtToken concurrently which is useless
	// and will cause overload on CAPI. We use a mutex to avoid this.
	t.refreshTokenMutex.Lock()
	defer t.refreshTokenMutex.Unlock()

	// We bypass the refresh if we are requesting the login endpoint, as it does not require a token,
	// and it leads to do 2 requests instead of one (refresh + actual login request).
	if req.URL.Path != "/"+t.VersionPrefix+"/watchers/login" && t.needsTokenRefresh() {
		if err := t.refreshJwtToken(req.Context()); err != nil {
			return nil, err
		}
	}

	if t.UserAgent != "" {
		req.Header.Add("User-Agent", t.UserAgent)
	}

	req.Header.Add("Authorization", "Bearer "+t.Token)

	return req, nil
}

// RoundTrip implements the RoundTripper interface.
func (t *JWTTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response

	attemptsCount := make(map[int]int)

	for {
		if log.IsLevelEnabled(log.TraceLevel) {
			// requestToDump := cloneRequest(req)
			dump, _ := httputil.DumpRequest(req, true)
			log.Tracef("req-jwt: %s", string(dump))
		}
		// Make the HTTP request.
		clonedReq := cloneRequest(req)

		clonedReq, err := t.prepareRequest(clonedReq)
		if err != nil {
			return nil, err
		}

		resp, err = t.transport().RoundTrip(clonedReq)
		if err != nil {
			// we had an error (network error for example), reset the token?
			t.ResetToken()
			return resp, fmt.Errorf("performing jwt auth: %w", err)
		}

		if resp != nil {
			log.Debugf("resp-jwt: %d", resp.StatusCode)
		}

		config, shouldRetry := t.RetryConfig.StatusCodeConfig[resp.StatusCode]
		if !shouldRetry {
			break
		}

		if attemptsCount[resp.StatusCode] >= config.MaxAttempts {
			log.Infof("max attempts reached for status code %d", resp.StatusCode)
			break
		}

		if config.InvalidateToken {
			log.Debugf("invalidating token for status code %d", resp.StatusCode)
			t.ResetToken()
		}

		log.Debugf("retrying request to %s", req.URL.String())

		attemptsCount[resp.StatusCode]++
		log.Infof("attempt %d out of %d", attemptsCount[resp.StatusCode], config.MaxAttempts)

		if config.Backoff {
			backoff := 2*attemptsCount[resp.StatusCode] + 5
			log.Infof("retrying in %d seconds (attempt %d of %d)", backoff, attemptsCount[resp.StatusCode], config.MaxAttempts)
			time.Sleep(time.Duration(backoff) * time.Second)
		}
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
	if t.Transport != nil {
		return t.Transport
	}

	return http.DefaultTransport
}
