package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func initAPIServer() (*apiserver.APIServer, error) {
	apiServer, err := apiserver.NewServer(cConfig.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}

	return apiServer, nil
}

func runAPIServer(apiServer *apiserver.APIServer) error {
	go func() {
		defer types.CatchPanic("crowdsec/runAPIServer")
		if err := apiServer.Run(); err != nil {
			log.Fatalf(err.Error())
		}

		defer apiServer.Close()
	}()
	return nil
}

func serveAPIServer(apiServer *apiserver.APIServer) {
	apiTomb.Go(func() error {
		defer types.CatchPanic("serveAPIServer")
		log.Info("local API server starting")
		<-apiTomb.Dying() // lock until go routine is dying
		if err := apiServer.Shutdown(); err != nil {
			log.Fatalf(err.Error())
		}
		return nil
	})
}
