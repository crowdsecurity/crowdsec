package v1

import (
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

/*prometheus*/
var LapiRouteHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_route_requests_total",
		Help: "Number of calls to each route per method.",
	},
	[]string{"route", "method"},
)

/*hits per machine*/
var LapiMachineHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_machine_requests_total",
		Help: "Number of calls to each route per method grouped by machines.",
	},
	[]string{"machine", "route", "method"},
)

/*hits per bouncer*/
var LapiBouncerHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_bouncer_requests_total",
		Help: "Number of calls to each route per method grouped by bouncers.",
	},
	[]string{"bouncer", "route", "method"},
)

/*
	keep track of the number of calls (per bouncer) that lead to nil/non-nil responses.

while it's not exact, it's a good way to know - when you have a rutpure bouncer - what is the rate of ok/ko answers you got from lapi
*/
var LapiNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_decisions_ko_total",
		Help: "Number of calls to /decisions that returned nil result.",
	},
	[]string{"bouncer"},
)

/*hits per bouncer*/
var LapiNonNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_decisions_ok_total",
		Help: "Number of calls to /decisions that returned non-nil result.",
	},
	[]string{"bouncer"},
)

var LapiResponseTime = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cs_lapi_request_duration_seconds",
		Help:    "Response time of LAPI",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.2, 0.3, 0.4, 0.5, 0.75, 1},
	},
	[]string{"endpoint", "method"})

func PrometheusBouncersHasEmptyDecision(c *gin.Context) {
	name, ok := c.Get("BOUNCER_NAME")
	if ok {
		LapiNilDecisions.With(prometheus.Labels{
			"bouncer": name.(string)}).Inc()
	}
}

func PrometheusBouncersHasNonEmptyDecision(c *gin.Context) {
	name, ok := c.Get("BOUNCER_NAME")
	if ok {
		LapiNonNilDecisions.With(prometheus.Labels{
			"bouncer": name.(string)}).Inc()
	}
}

func PrometheusMachinesMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		if claims != nil {
			if rawID, ok := claims["id"]; ok {
				machineID := rawID.(string)
				LapiMachineHits.With(prometheus.Labels{
					"machine": machineID,
					"route":   c.Request.URL.Path,
					"method":  c.Request.Method}).Inc()
			}
		}
		c.Next()
	}
}

func PrometheusBouncersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		name, ok := c.Get("BOUNCER_NAME")
		if ok {
			LapiBouncerHits.With(prometheus.Labels{
				"bouncer": name.(string),
				"route":   c.Request.URL.Path,
				"method":  c.Request.Method}).Inc()
		}
		c.Next()
	}
}

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		LapiRouteHits.With(prometheus.Labels{
			"route":  c.Request.URL.Path,
			"method": c.Request.Method}).Inc()
		c.Next()
		elapsed := time.Since(startTime)
		LapiResponseTime.With(prometheus.Labels{"method": c.Request.Method, "endpoint": c.Request.URL.Path}).Observe(elapsed.Seconds())
	}
}
