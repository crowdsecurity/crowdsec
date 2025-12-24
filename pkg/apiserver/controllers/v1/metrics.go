package v1

import (
	"cmp"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func PrometheusBouncersHasEmptyDecision(c *gin.Context) {
	bouncer, _ := getBouncerFromContext(c)
	if bouncer == nil {
		return
	}

	metrics.LapiNilDecisions.With(prometheus.Labels{
		"bouncer": bouncer.Name,
	}).Inc()
}

func PrometheusBouncersHasNonEmptyDecision(c *gin.Context) {
	bouncer, _ := getBouncerFromContext(c)
	if bouncer == nil {
		return
	}

	metrics.LapiNonNilDecisions.With(prometheus.Labels{
		"bouncer": bouncer.Name,
	}).Inc()
}

func PrometheusMachinesMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		machineID, _ := getMachineIDFromContext(c)
		if machineID == "" {
			return
		}

		metrics.LapiMachineHits.With(prometheus.Labels{
			"machine": machineID,
			"route":   cmp.Or(c.FullPath(), "invalid-endpoint"),
			"method":  c.Request.Method,
		}).Inc()
	}
}

func PrometheusBouncersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		bouncer, _ := getBouncerFromContext(c)
		if bouncer == nil {
			return
		}

		metrics.LapiBouncerHits.With(prometheus.Labels{
			"bouncer": bouncer.Name,
			"route":   cmp.Or(c.FullPath(), "invalid-endpoint"),
			"method":  c.Request.Method,
		}).Inc()
	}
}

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		metrics.LapiRouteHits.With(prometheus.Labels{
			"route":   cmp.Or(c.FullPath(), "invalid-endpoint"),
			"method": c.Request.Method,
		}).Inc()
		c.Next()

		elapsed := time.Since(startTime)
		metrics.LapiResponseTime.With(
			prometheus.Labels{
				"method": c.Request.Method,
				"endpoint": c.FullPath(),
			}).Observe(elapsed.Seconds())
	}
}
