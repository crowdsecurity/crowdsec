package v1

import (
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func PrometheusBouncersHasEmptyDecision(r *http.Request) {
	bouncer, _ := getBouncerFromContext(r)
	if bouncer != nil {
		metrics.LapiNilDecisions.With(prometheus.Labels{
			"bouncer": bouncer.Name,
		}).Inc()
	}
}

func PrometheusBouncersHasNonEmptyDecision(r *http.Request) {
	bouncer, _ := getBouncerFromContext(r)
	if bouncer != nil {
		metrics.LapiNonNilDecisions.With(prometheus.Labels{
			"bouncer": bouncer.Name,
		}).Inc()
	}
}

func PrometheusMachinesMiddleware() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			machineID, _ := getMachineIDFromContext(r)
			if machineID != "" {
				route := router.GetRoutePattern(r)
				if route == "" {
					route = "invalid-endpoint"
				}
				metrics.LapiMachineHits.With(prometheus.Labels{
					"machine": machineID,
					"route":   route,
					"method":  r.Method,
				}).Inc()
			}

			next.ServeHTTP(w, r)
		})
	}
}

func PrometheusBouncersMiddleware() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bouncer, _ := getBouncerFromContext(r)
			if bouncer != nil {
				route := router.GetRoutePattern(r)
				if route == "" {
					route = "invalid-endpoint"
				}
				metrics.LapiBouncerHits.With(prometheus.Labels{
					"bouncer": bouncer.Name,
					"route":   route,
					"method":  r.Method,
				}).Inc()
			}

			next.ServeHTTP(w, r)
		})
	}
}

func PrometheusMiddleware() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()

			route := router.GetRoutePattern(r)
			if route == "" {
				route = "invalid-endpoint"
			}

			metrics.LapiRouteHits.With(prometheus.Labels{
				"route":  route,
				"method": r.Method,
			}).Inc()

			next.ServeHTTP(w, r)

			elapsed := time.Since(startTime)
			metrics.LapiResponseTime.With(prometheus.Labels{"method": r.Method, "endpoint": route}).Observe(elapsed.Seconds())
		})
	}
}
