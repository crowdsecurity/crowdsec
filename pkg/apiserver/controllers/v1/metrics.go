package v1

import (
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

/*prometheus*/
var LapiRouteHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_route_requests_total",
		Help: "Number of calls to each route.",
	},
	[]string{"route", "method"},
)

/*hits per machine*/
var LapiMachineHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_machine_requests_total",
		Help: "Number of calls for each machine.",
	},
	[]string{"machine", "route", "method"},
)

/*hits per bouncer*/
var LapiBouncerHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_bouncer_requests_total",
		Help: "Number of calls for each bouncer.",
	},
	[]string{"bouncer", "route", "method"},
)

/* keep track of the number of calls (per bouncer) that lead to nil/non-nil responses.
while it's not exact, it's a good way to know - when you have a rutpure bouncer - what is the rate of ok/ko answers you got from lapi*/
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
		LapiRouteHits.With(prometheus.Labels{
			"route":  c.Request.URL.Path,
			"method": c.Request.Method}).Inc()
		c.Next()
	}
}
