package v1

import (
	"context"
	"net"

	// "github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/csprofiles"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
)

type Controller struct {
	Ectx          context.Context
	DBClient      *database.Client
	APIKeyHeader  string
	Middlewares   *middlewares.Middlewares
	Profiles      []*csprofiles.Runtime
	CAPIChan      chan []*models.Alert
	PluginChannel chan csplugin.ProfileAlert
	ConsoleConfig csconfig.ConsoleConfig
	TrustedIPs    []net.IPNet
}

type ControllerV1Config struct {
	DbClient      *database.Client
	Ctx           context.Context
	ProfilesCfg   []*csconfig.ProfileCfg
	CapiChan      chan []*models.Alert
	PluginChannel chan csplugin.ProfileAlert
	ConsoleConfig csconfig.ConsoleConfig
	TrustedIPs    []net.IPNet
}

func New(cfg *ControllerV1Config) (*Controller, error) {
	var err error

	profiles, err := csprofiles.NewProfile(cfg.ProfilesCfg)
	if err != nil {
		return &Controller{}, errors.Wrapf(err, "failed to compile profiles")
	}

	v1 := &Controller{
		Ectx:          cfg.Ctx,
		DBClient:      cfg.DbClient,
		APIKeyHeader:  middlewares.APIKeyHeader,
		Profiles:      profiles,
		CAPIChan:      cfg.CapiChan,
		PluginChannel: cfg.PluginChannel,
		ConsoleConfig: cfg.ConsoleConfig,
		TrustedIPs:    cfg.TrustedIPs,
	}
	v1.Middlewares, err = middlewares.NewMiddlewares(cfg.DbClient)
	if err != nil {
		return v1, err
	}
	return v1, nil
}
