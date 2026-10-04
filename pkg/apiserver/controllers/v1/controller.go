package v1

import (
	"cmp"
	"fmt"
	"net"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csprofiles"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Controller struct {
	DBClient     *database.Client
	APIKeyHeader string
	Middlewares  *middlewares.Middlewares
	Profiles     []*csprofiles.Runtime

	AlertsAddChan      chan []*models.Alert
	DecisionDeleteChan chan []*models.Decision

	PluginChannel   chan models.ProfileAlert
	ConsoleConfig   csconfig.ConsoleConfig
	TrustedIPs      []net.IPNet
	AutoRegisterCfg *csconfig.LocalAPIAutoRegisterCfg

	DecisionsStreamPageSize int
}

type ControllerV1Config struct {
	DbClient    *database.Client
	ProfilesCfg []*csconfig.ProfileCfg

	AlertsAddChan      chan []*models.Alert
	DecisionDeleteChan chan []*models.Decision

	PluginChannel   chan models.ProfileAlert
	ConsoleConfig   csconfig.ConsoleConfig
	TrustedIPs      []net.IPNet
	AutoRegisterCfg *csconfig.LocalAPIAutoRegisterCfg

	DecisionsStreamPageSize int
}

func New(cfg *ControllerV1Config) (*Controller, error) {
	var err error

	profiles, err := csprofiles.NewProfile(cfg.ProfilesCfg)
	if err != nil {
		return &Controller{}, fmt.Errorf("failed to compile profiles: %w", err)
	}

	v1 := &Controller{
		DBClient:           cfg.DbClient,
		APIKeyHeader:       middlewares.APIKeyHeader,
		Profiles:           profiles,
		AlertsAddChan:      cfg.AlertsAddChan,
		DecisionDeleteChan: cfg.DecisionDeleteChan,
		PluginChannel:      cfg.PluginChannel,
		ConsoleConfig:      cfg.ConsoleConfig,
		TrustedIPs:         cfg.TrustedIPs,
		AutoRegisterCfg:    cfg.AutoRegisterCfg,
		// 0 must never reach the query: it becomes LIMIT 0 and the stream would be silently empty.
		DecisionsStreamPageSize: cmp.Or(cfg.DecisionsStreamPageSize, defaultDecisionsStreamPageSize),
	}

	v1.Middlewares, err = middlewares.NewMiddlewares(cfg.DbClient)
	if err != nil {
		return v1, err
	}

	return v1, nil
}
