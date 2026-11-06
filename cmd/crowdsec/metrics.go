package main

import (
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/cache"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
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

		for _, a := range alerts {
			metrics.GlobalAlerts.With(prometheus.Labels{"reason": a.Scenario, "kind": a.Kind}).Set(float64(a.Count))
		}

		next.ServeHTTP(w, r)
	})
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

	mux := http.NewServeMux()
	mux.Handle("/metrics", computeDynamicMetrics(promhttp.Handler(), dbClient))

	// Only expose the Go pprof profiling endpoints when explicitly enabled.
	// They used to be reachable on the metrics listener via the blank
	// net/http/pprof import on DefaultServeMux; on a non-local listen_addr
	// that exposes profiling data and a cheap DoS. cscli support collects
	// pprof from this listener, so keep it available behind an opt-in.
	if config.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	if err := http.ListenAndServe(net.JoinHostPort(config.ListenAddr, strconv.Itoa(config.ListenPort)), mux); err != nil {
		// in time machine, we most likely have the LAPI using the port
		if !flags.haveTimeMachine() {
			log.WithError(err).Warning("serving metrics")
		}
	}
}
