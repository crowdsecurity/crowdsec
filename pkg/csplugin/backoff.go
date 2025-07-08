package csplugin

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/cenkalti/backoff/v5"
)

type backoffFactory func() backoff.BackOff

const (
	// time to wait before the first retry attempt.
	defaultInitialInterval = 1 * time.Second
	// how much the interval increases after each failure.
	defaultMultiplier = 2.0
	// add jitter to avoid synchronized retries across instances.
	defaultRandomizationFactor = 0.3
	// maximum delay between two consecutive retries.
	defaultMaxInterval = 30 * time.Second
	// total time limit for retries when MaxRetry is not specified.
	defaultMaxElapsedTime = 5 * time.Minute
)

var defaultBackoffFactory = func() backoff.BackOff {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = defaultInitialInterval
	bo.Multiplier = defaultMultiplier
	bo.RandomizationFactor = defaultRandomizationFactor
	bo.MaxInterval = defaultMaxInterval
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
	// the application is closing / reloading, stop notifying
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
		options = append(options, backoff.WithMaxElapsedTime(defaultMaxElapsedTime))
	}

	_, err := backoff.Retry(ctx, operation, options...)
	return err
}
