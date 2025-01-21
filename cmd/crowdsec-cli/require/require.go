package require

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func LAPI(c *csconfig.Config) error {
	if err := c.LoadAPIServer(true); err != nil {
		return fmt.Errorf("failed to load Local API: %w", err)
	}

	if c.DisableAPI {
		return errors.New("local API is disabled -- this command must be run on the local API machine")
	}

	return nil
}

func CAPI(c *csconfig.Config) error {
	if c.API.Server.OnlineClient == nil {
		return fmt.Errorf("no configuration for Central API (CAPI) in '%s'", c.FilePath)
	}

	return nil
}

func PAPI(c *csconfig.Config) error {
	if err := CAPI(c); err != nil {
		return err
	}

	if err := CAPIRegistered(c); err != nil {
		return err
	}

	if c.API.Server.OnlineClient.Credentials.PapiURL == "" {
		return errors.New("no PAPI URL in configuration")
	}

	return nil
}

func CAPIRegistered(c *csconfig.Config) error {
	if c.API.Server.OnlineClient.Credentials == nil {
		return errors.New("the Central API (CAPI) must be configured with 'cscli capi register'")
	}

	return nil
}

func DBClient(ctx context.Context, dbcfg *csconfig.DatabaseCfg) (*database.Client, error) {
	db, err := database.NewClient(ctx, dbcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

func DB(c *csconfig.Config) error {
	if err := c.LoadDBConfig(true); err != nil {
		return fmt.Errorf("this command requires direct database access (must be run on the local API machine): %w", err)
	}

	return nil
}

func Notifications(c *csconfig.Config) error {
	if c.ConfigPaths.NotificationDir == "" {
		return errors.New("config_paths.notification_dir is not set in crowdsec config")
	}

	return nil
}

func HubDownloader(ctx context.Context, c *csconfig.Config) *cwhub.Downloader {
	// set branch in config, and log if necessary
	branch := HubBranch(ctx, c)
	urlTemplate := HubURLTemplate(c)
	remote := &cwhub.Downloader{
		Branch:      branch,
		URLTemplate: urlTemplate,
	}

	return remote
}

// Hub initializes the hub. If a remote configuration is provided, it can be used to download the index and items.
// If no remote parameter is provided, the hub can only be used for local operations.
func Hub(c *csconfig.Config, logger *logrus.Logger) (*cwhub.Hub, error) {
	local := c.Hub

	if local == nil {
		return nil, errors.New("you must configure cli before interacting with hub")
	}

	if logger == nil {
		logger = logrus.New()
		logger.SetOutput(io.Discard)
	}

	hub, err := cwhub.NewHub(local, logger)
	if err != nil {
		return nil, err
	}

	if err := hub.Load(); err != nil {
		return nil, err
	}

	return hub, nil
}
