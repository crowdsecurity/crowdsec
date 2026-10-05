package v1

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

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

	DecisionsStream *csconfig.DecisionsStreamCfg
}

func New(cfg *ControllerV1Config) (*Controller, error) {
	var err error

	profiles, err := csprofiles.NewProfile(cfg.ProfilesCfg)
	if err != nil {
		return &Controller{}, fmt.Errorf("failed to compile profiles: %w", err)
	}

	pageSize := csconfig.DefaultDecisionsStreamPageSize
	if cfg.DecisionsStream != nil {
		pageSize = cfg.DecisionsStream.PageSize
	}

	// ent drops LIMIT for 0 and SQLite ignores a negative one: a page would be the whole table,
	// and the paging loop would never end.
	if pageSize <= 0 {
		log.Warningf("decisions_stream.page_size must be greater than 0 (got %d), using the default value of %d", pageSize, csconfig.DefaultDecisionsStreamPageSize)

		pageSize = csconfig.DefaultDecisionsStreamPageSize
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

		DecisionsStreamPageSize: pageSize,
	}

	v1.Middlewares, err = middlewares.NewMiddlewares(cfg.DbClient)
	if err != nil {
		return v1, err
	}

	return v1, nil
}
