package csplugin

import (
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type PluginBroker struct {
	ProfileConfigs []*csconfig.ProfileCfg
	PluginChannel  chan ProfileAlert
}

type ProfileAlert struct {
	ProfileID uint
	Alert     *models.Alert
}

func (pb *PluginBroker) Run() {
	for {
		profileAlert := <-pb.PluginChannel
		log.Infof("%+v ", profileAlert)
	}
}
