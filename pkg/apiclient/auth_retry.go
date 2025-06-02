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
	onBeforeRequest  func(attempt int)
}

func (r retryRoundTripper) ShouldRetry(statusCode int) bool {
	return slices.Contains(r.retryStatusCodes, statusCode)
}

func (r retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	maxAttempts := r.maxAttempts
	if fflag.DisableHttpRetryBackoff.IsEnabled() {
		maxAttempts = 1
	}

	// Build a backoff policy:
	//
	// - If r.withBackOff is true, use exponential + jitter.
	// - Otherwise, use a constant backoff of 0 (i.e. no waiting)

	var bo backoff.BackOff
	if r.withBackOff {
		exp := backoff.NewExponentialBackOff()
		exp.InitialInterval = 200 * time.Millisecond
		exp.MaxInterval = 20 * time.Second
		bo = exp
	} else {
		// backoff is disabled, policy of "no wait"
		bo = backoff.NewConstantBackOff(0)
	}

	attempt := uint(0)

	operation := func() (*http.Response, error) {
		if r.onBeforeRequest != nil {
			r.onBeforeRequest(int(attempt))
		}

		clonedReq := cloneRequest(req)

		resp, err := r.next.RoundTrip(clonedReq)
		if err != nil {
			log.Errorf("error while performing request: %s; %d retries left", err, maxAttempts-attempt-1)
			return resp, nil
		}

		log.Infof("retrying... (attempt %d of %d)", attempt+1, maxAttempts)

		if !r.ShouldRetry(resp.StatusCode) {
			return resp, nil
		}

		resp.Body.Close()

	        return nil, fmt.Errorf("retryable status: %d", resp.StatusCode)
	}

	resp, err := backoff.Retry(req.Context(), operation,
		backoff.WithBackOff(bo),
		backoff.WithMaxTries(r.maxAttempts),
	)

	if err != nil {
		// can it be a context cancelation?? XXX
		return nil, err
	}

	return resp, nil
}
