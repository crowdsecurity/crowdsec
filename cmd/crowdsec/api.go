package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func initAPIServer(cConfig *csconfig.Config) (*apiserver.APIServer, error) {
	apiServer, err := apiserver.NewServer(cConfig.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}

	if hasPlugins(cConfig.API.Server.Profiles) {
		log.Info("initing plugin broker")
		err = pluginBroker.Init(cConfig.API.Server.Profiles, cConfig.ConfigPaths)
		if err == nil {
			log.Info("inited plugin broker")
			apiServer.AttachPluginBroker(&pluginBroker)
		} else {
			log.Error(err)
		}
	}

	err = apiServer.InitController()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}

	return apiServer, nil
}

func serveAPIServer(apiServer *apiserver.APIServer) {
	apiTomb.Go(func() error {
		defer types.CatchPanic("crowdsec/serveAPIServer")
		go func() {
			defer types.CatchPanic("crowdsec/runAPIServer")
			if err := apiServer.Run(); err != nil {
				log.Fatalf(err.Error())
			}
		}()

		go func() {
			pluginBroker.Run()
		}()
		<-apiTomb.Dying() // lock until go routine is dying
		log.Infof("serve: shutting down api server")
		if err := apiServer.Shutdown(); err != nil {
			return err
		}
		return nil
	})
}

func hasPlugins(profiles []*csconfig.ProfileCfg) bool {
	for _, profile := range profiles {
		if len(profile.Notifications) != 0 {
			return true
		}
	}
	return false
}
