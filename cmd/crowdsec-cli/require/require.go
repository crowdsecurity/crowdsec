package require

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

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

func Notifications(c *csconfig.Config) error {
	if c.ConfigPaths.NotificationDir == "" {
		return fmt.Errorf("config_paths.notification_dir is not set in crowdsec config")
	}

	return nil
}

// RemoteHub returns the configuration required to download hub index and items: url, branch, etc.
func RemoteHub(c *csconfig.Config) *cwhub.RemoteHubCfg {
	// set branch in config, and log if necessary
	branch := HubBranch(c)
	remote := &cwhub.RemoteHubCfg{
		Branch:      branch,
		URLTemplate: "https://hub-cdn.crowdsec.net/%s/%s",
		// URLTemplate: "http://localhost:8000/crowdsecurity/%s/hub/%s",
		IndexPath: ".index.json",
	}

	return remote
}

// Hub initializes the hub. If a remote configuration is provided, it can be used to download the index and items.
// If no remote parameter is provided, the hub can only be used for local operations.
func Hub(c *csconfig.Config, remote *cwhub.RemoteHubCfg, logger *logrus.Logger) (*cwhub.Hub, error) {
	local := c.Hub

	if local == nil {
		return nil, fmt.Errorf("you must configure cli before interacting with hub")
	}

	if logger == nil {
		logger = logrus.New()
		logger.SetOutput(io.Discard)
	}

	hub, err := cwhub.NewHub(local, remote, false, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to read Hub index: %w. Run 'sudo cscli hub update' to download the index again", err)
	}

	return hub, nil
}
