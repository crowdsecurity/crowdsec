package apiclient

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/cenkalti/backoff/v5"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

type retryRoundTripper struct {
	next             http.RoundTripper
	maxAttempts      uint
	retryStatusCodes []int
	withBackOff      bool
}

func (r retryRoundTripper) ShouldRetry(statusCode int) bool {
	return slices.Contains(r.retryStatusCodes, statusCode)
}

func (r retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	maxAttempts := max(r.maxAttempts, 1)
	if fflag.DisableHttpRetryBackoff.IsEnabled() {
		maxAttempts = 1
	}

	var bo backoff.BackOff

	if r.withBackOff {
		// Use exponential + jitter; the default values are:
		//
		// DefaultInitialInterval     = 500 * time.Millisecond
		// DefaultRandomizationFactor = 0.5
		// DefaultMultiplier          = 1.5
		// DefaultMaxInterval         = 60 * time.Second
		exp := backoff.NewExponentialBackOff()
		exp.InitialInterval = 20 * time.Second
		exp.Multiplier = 2
		bo = exp
	} else {
		// backoff is disabled, policy of "no wait"
		bo = backoff.NewConstantBackOff(0)
	}

	attemptLeft := maxAttempts

	operation := func() (*http.Response, error) {
		clonedReq := cloneRequest(req)

		attemptLeft--

		resp, err := r.next.RoundTrip(clonedReq)
		if err != nil {
			if attemptLeft > 0 {
				log.Errorf("while performing request: %s; %d retries left", err, attemptLeft)
			}
			return nil, fmt.Errorf("retryable error: %w", err)
		}

		if r.ShouldRetry(resp.StatusCode) {
			log.Errorf("request returned status %d: %s; %d retries left", resp.StatusCode, resp.Status, attemptLeft)
	        	return nil, fmt.Errorf("retryable status: %d", resp.StatusCode)
		}

		return resp, nil
	}

	resp, err := backoff.Retry(req.Context(), operation,
		backoff.WithBackOff(bo),
		backoff.WithMaxTries(maxAttempts),
	)

	if err != nil {
		return nil, err
	}

	return resp, nil
}
