package require

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func LAPI(c *csconfig.Config) error {
	if err := c.LoadAPIServer(); err != nil {
		return fmt.Errorf("failed to load Local API: %w", err)
	}

	if c.DisableAPI {
		return fmt.Errorf("local API is disabled -- this command must be run on the local API machine")
	}

	return nil
}

func CAPI(c *csconfig.Config) error {
	if c.API.Server.OnlineClient == nil {
		return fmt.Errorf("no configuration for Central API (CAPI) in '%s'", *c.FilePath)
	}
	return nil
}

func PAPI(c *csconfig.Config) error {
	if c.API.Server.OnlineClient.Credentials.PapiURL == "" {
		return fmt.Errorf("no PAPI URL in configuration")
	}
	return nil
}

func CAPIRegistered(c *csconfig.Config) error {
	if c.API.Server.OnlineClient.Credentials == nil {
		return fmt.Errorf("the Central API (CAPI) must be configured with 'cscli capi register'")
	}

	return nil
}

func DB(c *csconfig.Config) error {
	if err := c.LoadDBConfig(); err != nil {
		return fmt.Errorf("this command requires direct database access (must be run on the local API machine): %w", err)
	}
	return nil
}

func Profiles(c *csconfig.Config) error {
	if err := c.API.Server.LoadProfiles(); err != nil {
		return fmt.Errorf("while loading profiles: %w", err)
	}

	return nil
}

func Notifications(c *csconfig.Config) error {
	if c.ConfigPaths.NotificationDir == "" {
		return fmt.Errorf("config_paths.notification_dir is not set in crowdsec config")
	}

	return nil
}

func Hub (c *csconfig.Config) error {
	if err := c.LoadHub(); err != nil {
		return err
	}

	if c.Hub == nil {
		return fmt.Errorf("you must configure cli before interacting with hub")
	}

	if err := cwhub.SetHubBranch(); err != nil {
		return fmt.Errorf("while setting hub branch: %w", err)
	}

	if err := cwhub.GetHubIdx(c.Hub); err != nil {
		return fmt.Errorf("failed to read Hub index: '%w'. Run 'sudo cscli hub update' to download the index again", err)
	}

	return nil
}
