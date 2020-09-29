package main

import (
	"fmt"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	log "github.com/sirupsen/logrus"
)

func initAPIServer() (*apiserver.APIServer, error) {
	apiServer, err := apiserver.NewServer(cConfig.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}

	return apiServer, nil
}

func runAPIServer(apiServer *apiserver.APIServer) (*http.Server, error) {
	handler, err := apiServer.Router()
	if err != nil {
		return nil, fmt.Errorf("unable to get gin router: %s", err)
	}
	httpAPIServer = http.Server{
		Addr:    cConfig.API.Server.ListenURI,
		Handler: handler,
	}
	go func() {
		if err := httpAPIServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf(err.Error())
		}
		defer apiServer.Close()
	}()
	return &httpAPIServer, nil
}

func serveAPIServer(httpAPIServer *http.Server) {
	apiTomb.Go(func() error {
		log.Info("local API server starting")
		<-apiTomb.Dying() // lock until go routine is dying
		httpAPIServer.Shutdown(nil)
		return nil
	})
}
