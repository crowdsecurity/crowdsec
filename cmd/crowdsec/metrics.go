package main

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/cache"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func computeDynamicMetrics(next http.Handler, dbClient *database.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer trace.ReportPanic()

		// update cache metrics (stash)
		cache.UpdateCacheMetrics()
		// update cache metrics (regexp)
		exprhelpers.UpdateRegexpCacheMetrics()

		// decision metrics are only relevant for LAPI
		if dbClient == nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		decisions, err := dbClient.QueryDecisionCountByScenario(ctx)
		if err != nil {
			log.WithError(err).Error("querying decisions for metrics")
			next.ServeHTTP(w, r)

			return
		}

		metrics.GlobalActiveDecisions.Reset()

		for _, d := range decisions {
			metrics.GlobalActiveDecisions.With(prometheus.Labels{"reason": d.Scenario, "origin": d.Origin, "action": d.Type}).Set(float64(d.Count))
		}

		metrics.GlobalAlerts.Reset()

		alertsFilter := map[string][]string{
			"include_capi": {"false"},
		}

		alerts, err := dbClient.AlertsCountPerScenario(ctx, alertsFilter)
		if err != nil {
			log.WithError(err).Error("querying alerts for metrics")
			next.ServeHTTP(w, r)

			return
		}

		for k, v := range alerts {
			metrics.GlobalAlerts.With(prometheus.Labels{"reason": k}).Set(float64(v))
		}

		machines, err := dbClient.ListMachines(ctx)
		if err != nil {
			log.WithError(err).Error("listing machines for metrics")
			next.ServeHTTP(w, r)

			return
		}

		updateMachinesHeartbeatMetric(machines)

		next.ServeHTTP(w, r)
	})
}

func updateMachinesHeartbeatMetric(machines []*ent.Machine) {
	metrics.GlobalMachinesHeartbeat.Reset()

	for _, m := range machines {
		if m.LastHeartbeat == nil {
			continue
		}

		elapsed := time.Now().UTC().Sub(*m.LastHeartbeat)
		metrics.GlobalMachinesHeartbeat.With(prometheus.Labels{"machine": m.MachineId}).Set(elapsed.Seconds())
	}
}

func registerPrometheus(config *csconfig.PrometheusCfg) {
	if !config.Enabled {
		return
	}

	if err := metrics.RegisterMetrics(config.Level); err != nil {
		log.WithError(err).Error("registering prometheus metrics")
		return
	}
}

func servePrometheus(config *csconfig.PrometheusCfg, dbClient *database.Client, agentReady chan bool) {
	<-agentReady

	if !config.Enabled {
		return
	}

	http.Handle("/metrics", computeDynamicMetrics(promhttp.Handler(), dbClient))

	if err := http.ListenAndServe(net.JoinHostPort(config.ListenAddr, strconv.Itoa(config.ListenPort)), nil); err != nil {
		// in time machine, we most likely have the LAPI using the port
		if !flags.haveTimeMachine() {
			log.WithError(err).Warning("serving metrics")
		}
	}
}
