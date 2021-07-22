package v1

import (
	"context"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Controller struct {
	Ectx          context.Context
	DBClient      *database.Client
	APIKeyHeader  string
	Middlewares   *middlewares.Middlewares
	Profiles      []*csconfig.ProfileCfg
	CAPIChan      chan []*models.Alert
	PluginChannel chan csplugin.ProfileAlert
}

func New(dbClient *database.Client, ctx context.Context, profiles []*csconfig.ProfileCfg, capiChan chan []*models.Alert, pluginChannel chan csplugin.ProfileAlert) (*Controller, error) {
	var err error
	v1 := &Controller{
		Ectx:          ctx,
		DBClient:      dbClient,
		APIKeyHeader:  middlewares.APIKeyHeader,
		Profiles:      profiles,
		CAPIChan:      capiChan,
		PluginChannel: pluginChannel,
	}
	v1.Middlewares, err = middlewares.NewMiddlewares(dbClient)
	if err != nil {
		return v1, err
	}

	return v1, nil
}
