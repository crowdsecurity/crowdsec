package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func initAPIServer(ctx context.Context, cConfig *csconfig.Config) (*apiserver.APIServer, error) {
	if cConfig.API.Server.OnlineClient == nil || cConfig.API.Server.OnlineClient.Credentials == nil {
		log.Info("push and pull to Central API disabled")
	}

	apiServer, err := apiserver.NewServer(ctx, cConfig.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	if hasPlugins(cConfig.API.Server.Profiles) {
		log.Info("initiating plugin broker")
		// On windows, the plugins are always run as medium-integrity processes, so we don't care about plugin_config
		if cConfig.PluginConfig == nil && runtime.GOOS != "windows" {
			return nil, errors.New("plugins are enabled, but the plugin_config section is missing in the configuration")
		}

		if cConfig.ConfigPaths.NotificationDir == "" {
			return nil, errors.New("plugins are enabled, but config_paths.notification_dir is not defined")
		}

		if cConfig.ConfigPaths.PluginDir == "" {
			return nil, errors.New("plugins are enabled, but config_paths.plugin_dir is not defined")
		}

		err = pluginBroker.Init(ctx, cConfig.PluginConfig, cConfig.API.Server.Profiles, cConfig.ConfigPaths)
		if err != nil {
			return nil, fmt.Errorf("unable to run plugin broker: %w", err)
		}

		log.Info("initiated plugin broker")
		apiServer.AttachPluginBroker(&pluginBroker)
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

		pluginTomb.Go(func() error {
			pluginBroker.Run(&pluginTomb)
			return nil
		})

		<-apiTomb.Dying() // lock until go routine is dying
		pluginTomb.Kill(nil)
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
