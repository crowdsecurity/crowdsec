package csplugin

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/cenkalti/backoff/v5"
)

type backoffFactory func() backoff.BackOff

var defaultBackoffFactory = func() backoff.BackOff {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 1 * time.Second
	bo.Multiplier = 2.0
	bo.RandomizationFactor = 0.3
	bo.MaxInterval = 30 * time.Second
	return bo
}

// retryWithBackoff retries the given function according to cfg.
func retryWithBackoff(
	ctx context.Context,
	cfg PluginConfig,
	logger logrus.FieldLogger,
	fn func(ctx context.Context) error,
	newBackoff backoffFactory,
) error {
	// the world is falling apart, don't notify (XXX: or should we?)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	var attempt uint64
	onRetry := func(err error, next time.Duration) {
		attempt++
		logger.WithFields(logrus.Fields{
			"attempt": attempt,
			"next":    next.String(),
		}).Warnf("notify attempt failed: %v", err)
	}

	operation := func() (struct{}, error) {
		attemptCtx, cancel := context.WithTimeout(ctx, cfg.TimeOut)
		defer cancel()
		return struct{}{}, fn(attemptCtx)
	}

	bo := newBackoff()

	options := []backoff.RetryOption{
		backoff.WithBackOff(bo),
		backoff.WithNotify(onRetry),
	}

	if cfg.MaxRetry > 0 {
		options = append(options, backoff.WithMaxTries(cfg.MaxRetry+1))
	} else {
		options = append(options, backoff.WithMaxElapsedTime(5*time.Minute))
	}

	_, err := backoff.Retry(ctx, operation, options...)
	return err
}
