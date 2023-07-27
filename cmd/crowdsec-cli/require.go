package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func requireLAPI(c *csconfig.Config) error {
	if err := c.LoadAPIServer(); err != nil {
		return fmt.Errorf("failed to load Local API: %w", err)
	}

	if c.DisableAPI {
		return fmt.Errorf("local API is disabled -- this command must be run on the local API machine")
	}

	return nil
}

func requireCAPI(c *csconfig.Config) error {
	if c.API.Server.OnlineClient == nil {
		return fmt.Errorf("no configuration for Central API (CAPI) in '%s'", *c.FilePath)
	}
	return nil
}

func requireEnrolled(c *csconfig.Config) error {
	if err := requireCAPI(c); err != nil {
		return err
	}

	if c.API.Server.OnlineClient.Credentials == nil {
		return fmt.Errorf("the Central API (CAPI) must be configured with 'cscli capi register'")
	}

	return nil
}

func requireDB(c *csconfig.Config) error {
	if err := c.LoadDBConfig(); err != nil {
		return fmt.Errorf("this command requires direct database access (must be run on the local API machine): %w", err)
	}
	return nil
}

