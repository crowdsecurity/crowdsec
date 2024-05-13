package apiclient

type StatusCodeConfig struct {
	MaxAttempts     int
	Backoff         bool
	InvalidateToken bool
}

type RetryConfig struct {
	StatusCodeConfig map[int]StatusCodeConfig
}

type RetryConfigOption func(*RetryConfig)

func NewRetryConfig(options ...RetryConfigOption) *RetryConfig {
	rc := &RetryConfig{
		StatusCodeConfig: make(map[int]StatusCodeConfig),
	}
	for _, opt := range options {
		opt(rc)
	}
	return rc
}

func WithStatusCodeConfig(statusCode int, maxAttempts int, backOff bool, invalidateToken bool) RetryConfigOption {
	return func(rc *RetryConfig) {
		rc.StatusCodeConfig[statusCode] = StatusCodeConfig{
			MaxAttempts:     maxAttempts,
			Backoff:         backOff,
			InvalidateToken: invalidateToken,
		}
	}
}
