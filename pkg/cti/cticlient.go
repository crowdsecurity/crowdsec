package cti

import (
	"fmt"
)

const CTIBaseURL = "https://cti.api.crowdsec.net/v2"

// NewCTIClient creates a new CTI client with the correct URL and any required configuration.
func NewCTIClient(apiKey string, opts ...ClientOption) (*ClientWithResponses, error) {
	provider, err := NewAPIKeyProvider(apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key provider: %w", err)
	}

	opts = append(opts, WithRequestEditorFn(provider.Intercept))

	return NewClientWithResponses(CTIBaseURL, opts...)
}
