package v1

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func PrometheusBouncersHasEmptyDecision(c *gin.Context) {
	bouncer, _ := getBouncerFromContext(c)
	if bouncer != nil {
		metrics.LapiNilDecisions.With(prometheus.Labels{
			"bouncer": bouncer.Name,
		}).Inc()
	}
}

func PrometheusBouncersHasNonEmptyDecision(c *gin.Context) {
	bouncer, _ := getBouncerFromContext(c)
	if bouncer != nil {
		metrics.LapiNonNilDecisions.With(prometheus.Labels{
			"bouncer": bouncer.Name,
		}).Inc()
	}
}

func PrometheusMachinesMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		machineID, _ := getMachineIDFromContext(c)
		if machineID != "" {
			fullPath := c.FullPath()
			if fullPath == "" {
				fullPath = "invalid-endpoint"
			}
			metrics.LapiMachineHits.With(prometheus.Labels{
				"machine": machineID,
				"route":   fullPath,
				"method":  c.Request.Method,
			}).Inc()
		}

		c.Next()
	}
}

func PrometheusBouncersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		bouncer, _ := getBouncerFromContext(c)
		if bouncer != nil {
			fullPath := c.FullPath()
			if fullPath == "" {
				fullPath = "invalid-endpoint"
			}
			metrics.LapiBouncerHits.With(prometheus.Labels{
				"bouncer": bouncer.Name,
				"route":   fullPath,
				"method":  c.Request.Method,
			}).Inc()
		}

		c.Next()
	}
}

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		fullPath := c.FullPath()
		if fullPath == "" {
			fullPath = "invalid-endpoint"
		}

		metrics.LapiRouteHits.With(prometheus.Labels{
			"route":  fullPath,
			"method": c.Request.Method,
		}).Inc()
		c.Next()

		elapsed := time.Since(startTime)
		metrics.LapiResponseTime.With(prometheus.Labels{"method": c.Request.Method, "endpoint": c.FullPath()}).Observe(elapsed.Seconds())
	}
}
