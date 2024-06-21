package apiclient

import (
	"math/rand"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

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

	for i := range maxAttempts {
		if i > 0 {
			if r.withBackOff {
				//nolint:gosec
				backoff += 10 + rand.Intn(20)
			}

			log.Infof("retrying in %d seconds (attempt %d of %d)", backoff, i+1, r.maxAttempts)

			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(time.Duration(backoff) * time.Second):
			}
		}

		if r.onBeforeRequest != nil {
			r.onBeforeRequest(i)
		}

		clonedReq := cloneRequest(req)

		resp, err = r.next.RoundTrip(clonedReq)
		if err != nil {
			if left := maxAttempts - i - 1; left > 0 {
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
