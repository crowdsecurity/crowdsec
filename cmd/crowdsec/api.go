package main

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

const accessLogFilename = "crowdsec_api.log"

func initAPIServer(ctx context.Context, cConfig *csconfig.Config) (*apiserver.APIServer, error) {
	if cConfig.API.Server.OnlineClient == nil || cConfig.API.Server.OnlineClient.Credentials == nil {
		log.Info("push and pull to Central API disabled")
	}

	accessLogger := cConfig.API.Server.NewAccessLogger(cConfig.Common.LogConfig, accessLogFilename)

	apiServer, err := apiserver.NewServer(ctx, cConfig.API.Server, accessLogger)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	err = apiServer.InitPlugins(ctx, cConfig, &pluginBroker)
	if err != nil {
		return nil, err
	}

	err = apiServer.InitController()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	return apiServer, nil
}

func serveAPIServer(ctx context.Context, apiServer *apiserver.APIServer) {
	apiReady := make(chan bool, 1)

	apiTomb.Go(func() error {
		defer trace.CatchPanic("crowdsec/serveAPIServer")

		go func() {
			defer trace.CatchPanic("crowdsec/runAPIServer")

			log.Debugf("serving API after %s ms", time.Since(crowdsecT0))

			if err := apiServer.Run(ctx, apiReady); err != nil {
				log.Fatal(err)
			}
		}()

		pluginTomb.Go(func() error {
			pluginBroker.Run(&pluginTomb)
			return nil
		})

		<-apiTomb.Dying() // lock until go routine is dying
		pluginTomb.Kill(nil)
		log.Infof("serve: shutting down api server")

		return apiServer.Shutdown(ctx)
	})
	<-apiReady
}
