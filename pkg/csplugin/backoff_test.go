package csplugin

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errFail        = errors.New("fail")
	errAlwaysFails = errors.New("always fails")
)

type fakeBackoff struct {
	retries []time.Duration
	idx     int
}

func (f *fakeBackoff) NextBackOff() time.Duration {
	if f.idx >= len(f.retries) {
		return backoff.Stop
	}
	d := f.retries[f.idx]
	f.idx++
	return d
}

func (f *fakeBackoff) Reset() {
	f.idx = 0
}

func newFakeBackoff(durations ...time.Duration) backoffFactory {
	return func() backoff.BackOff {
		return &fakeBackoff{retries: durations}
	}
}

func TestRetryWithBackoff_SuccessAfterRetries(t *testing.T) {
	discard := logrus.New()
	discard.Out = io.Discard

	ctx := t.Context()

	var calls int

	fn := func(_ context.Context) error {
		calls++
		if calls < 3 {
			return errFail
		}

		return nil
	}

	cfg := PluginConfig{TimeOut: 50 * time.Millisecond, MaxRetry: 5}
	err := retryWithBackoff(ctx, cfg, discard, fn, newFakeBackoff(
		0, 0, 0,
		))
	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestRetryWithBackoff_ExhaustsRetries(t *testing.T) {
	discard := logrus.New()
	discard.Out = io.Discard

	ctx := t.Context()

	fn := func(_ context.Context) error {
		return errAlwaysFails
	}

	cfg := PluginConfig{TimeOut: 50 * time.Millisecond, MaxRetry: 2}
	err := retryWithBackoff(ctx, cfg, discard, fn, newFakeBackoff(
		0, 0, 0,
		))
	require.ErrorIs(t, err, errAlwaysFails)
}

func TestRetryWithBackoff_ContextCanceled(t *testing.T) {
	discard := logrus.New()
	discard.Out = io.Discard

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var calls int
	fn := func(ctx context.Context) error {
		calls++
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	cfg := PluginConfig{TimeOut: 50 * time.Millisecond, MaxRetry: 3}
	err := retryWithBackoff(ctx, cfg, discard, fn, newFakeBackoff(0,0,0))
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, calls)

	// XXX: do we attempt to notify if ctx is canceled?
	// assert.Equal(t, 1, calls, "fn should be called once and fail with canceled")
}

func TestRetryWithBackoff_PerAttemptTimeout(t *testing.T) {
	discard := logrus.New()
	discard.Out = io.Discard

	fn := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	cfg := PluginConfig{TimeOut: 10 * time.Millisecond, MaxRetry: 1}
	err := retryWithBackoff(t.Context(), cfg, discard, fn, newFakeBackoff(0))
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRetryWithBackoff_MaxElapsedTime(t *testing.T) {
	discard := logrus.New()
	discard.Out = io.Discard

	ctx := t.Context()

	fn := func(_ context.Context) error {
		return errAlwaysFails
	}

	// MaxRetry = 0 -> unlimited retries
	// but we override elapsed time to a very short value
	cfg := PluginConfig{TimeOut: 10 * time.Millisecond, MaxRetry: 0}

	err := retryWithBackoff(ctx, cfg, discard, fn, newFakeBackoff(0, 0, 0))
	require.Error(t, err)
	assert.ErrorIs(t, err, errAlwaysFails)
}

func TestRetryWithBackoff_SuccessFirstTry(t *testing.T) {
	discard := logrus.New()
	discard.Out = io.Discard

	ctx := t.Context()

	fn := func(_ context.Context) error {
		return nil
	}

	cfg := PluginConfig{TimeOut: 50 * time.Millisecond, MaxRetry: 3}
	err := retryWithBackoff(ctx, cfg, discard, fn, newFakeBackoff(0, 0, 0))
	require.NoError(t, err)
}

