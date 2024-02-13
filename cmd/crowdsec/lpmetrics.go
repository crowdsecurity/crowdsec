package main

import (
	"context"
	"net/http"
        log "github.com/sirupsen/logrus"
        "github.com/blackfireio/osinfo"
	"time"

        "github.com/crowdsecurity/go-cs-lib/ptr"
        "github.com/crowdsecurity/go-cs-lib/trace"

        "github.com/crowdsecurity/crowdsec/pkg/acquisition"
        "github.com/crowdsecurity/crowdsec/pkg/apiclient"
        "github.com/crowdsecurity/crowdsec/pkg/csconfig"
        "github.com/crowdsecurity/crowdsec/pkg/cwversion"
        "github.com/crowdsecurity/crowdsec/pkg/fflag"
        "github.com/crowdsecurity/crowdsec/pkg/models"
)

func detectOs() (string, string) {
	if cwversion.System == "docker" {
		return "docker", ""
	}

	osInfo, err := osinfo.GetOSInfo()
	if err != nil {
		return cwversion.System, "???"
	}

	return osInfo.Name, osInfo.Version
}

func lpMetricsPayload(consoleCfg *csconfig.ConsoleConfig, datasources []acquisition.DataSource, windowSize int, utcStartupTimestamp int64) models.AllMetrics {
	meta := &models.MetricsMeta{
		UtcStartupTimestamp: float64(utcStartupTimestamp),
		WindowSizeSeconds: int64(windowSize),
	}

	osName, osVersion := detectOs()

	os := &models.OSversion{
		Name: osName,
		Version: osVersion,
	}

	features := fflag.Crowdsec.GetEnabledFeatures()

	datasourceMap := map[string]int64{}

	for _, ds := range datasources {
		datasourceMap[ds.GetName()] += 1
	}

	return models.AllMetrics{
                LogProcessors: []models.LogProcessorsMetrics{
                                {
                                &models.LogProcessorsMetricsItems0{
                                        BaseMetrics: models.BaseMetrics{
						Meta: meta,
                                                Os: os,
                                                Version: ptr.Of(cwversion.VersionStr()),
						FeatureFlags: features,
                                        },
					ConsoleOptions: consoleCfg.EnabledOptions(),
					Datasources: datasourceMap,
                                },
                        },
                },
	}
}

// lpMetrics collects metrics from the LP and sends them to the LAPI
func lpMetrics(client *apiclient.ApiClient, consoleCfg *csconfig.ConsoleConfig, datasources []acquisition.DataSource) error {
        defer trace.CatchPanic("crowdsec/runLpMetrics")
        log.Trace("Starting lpMetrics goroutine")

	windowSize := 6
	utcStartupEpoch := time.Now().Unix()
	
	met := lpMetricsPayload(consoleCfg, datasources, windowSize, utcStartupEpoch)

	ticker := time.NewTicker(time.Duration(windowSize) * time.Second)

        log.Tracef("Sending lp metrics every %d seconds", windowSize)

LOOP:
	for {
		select {
		case <-ticker.C:
			met.LogProcessors[0][0].Meta.UtcNowTimestamp = float64(time.Now().Unix())

			_, resp, err := client.UsageMetrics.Add(context.Background(), &met)
			if err != nil {
				log.Errorf("failed to send lp metrics: %s", err)
				continue
			}

			if resp.Response.StatusCode != http.StatusCreated {
				log.Errorf("failed to send lp metrics: %s", resp.Response.Status)
				continue
			}

			log.Tracef("lp usage metrics sent")
		case <-lpMetricsTomb.Dying():
			break LOOP
		}
	}

	ticker.Stop()
	
        return nil
}
