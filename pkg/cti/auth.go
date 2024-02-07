package cti

import (
        "github.com/deepmap/oapi-codegen/pkg/securityprovider"
)

func NewAPIKeyProvider(apiKey string) (*securityprovider.SecurityProviderApiKey, error) {
	return securityprovider.NewSecurityProviderApiKey("header", "x-api-key", apiKey)
}
