package main

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func initAPIServer(cConfig *csconfig.Config) (*apiserver.APIServer, error) {
	if cConfig.API.Server.OnlineClient == nil || cConfig.API.Server.OnlineClient.Credentials == nil {
		log.Info("push and pull to Central API disabled")
	}

	apiServer, err := apiserver.NewServer(cConfig.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	err = apiServer.InitController()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	return apiServer, nil
}

func serveAPIServer(apiServer *apiserver.APIServer) {
	apiReady := make(chan bool, 1)
	apiTomb.Go(func() error {
		defer trace.CatchPanic("crowdsec/serveAPIServer")
		go func() {
			defer trace.CatchPanic("crowdsec/runAPIServer")
			log.Debugf("serving API after %s ms", time.Since(crowdsecT0))
			if err := apiServer.Run(apiReady); err != nil {
				log.Fatal(err)
			}
		}()

		<-apiTomb.Dying() // lock until go routine is dying
		log.Infof("serve: shutting down api server")
		return apiServer.Shutdown()
	})
	<-apiReady
}

func hasPlugins(profiles []*csconfig.ProfileCfg) bool {
	for _, profile := range profiles {
		if len(profile.Notifications) != 0 {
			return true
		}
	}
	return false
}
