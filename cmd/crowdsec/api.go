package main

import (
	"fmt"
	"net/http"

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

func runAPIServer(apiServer *apiserver.APIServer) (*http.Server, error) {
	handler, err := apiServer.Router()
	if err != nil {
		return nil, fmt.Errorf("unable to get gin router: %s", err)
	}
	httpAPIServer = http.Server{
		Addr:    apiServer.URL,
		Handler: handler,
	}
	go func() {
		defer types.CatchPanic("crowdsec/runAPIServer")
		if apiServer.TLS != nil && apiServer.TLS.CertFilePath != "" && apiServer.TLS.KeyFilePath != "" {
			if err := httpAPIServer.ListenAndServeTLS(apiServer.TLS.CertFilePath, apiServer.TLS.KeyFilePath); err != nil {
				log.Fatalf(err.Error())
			}
		} else {
			if err := httpAPIServer.ListenAndServe(); err != http.ErrServerClosed {
				log.Fatalf(err.Error())
			}
		}

		defer apiServer.Close()
	}()
	return &httpAPIServer, nil
}

func serveAPIServer(httpAPIServer *http.Server) {
	apiTomb.Go(func() error {
		defer types.CatchPanic("serveAPIServer")
		log.Info("local API server starting")
		<-apiTomb.Dying() // lock until go routine is dying
		if err := httpAPIServer.Shutdown(nil); err != nil {
			log.Fatalf(err.Error())
		}
		return nil
	})
}
