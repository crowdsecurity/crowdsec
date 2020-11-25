package v1

import (
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

/*prometheus*/
var ApilRouteHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_apil_route_calls",
		Help: "Number of calls to each route.",
	},
	[]string{"route", "method"},
)

/*hits per machine*/
var ApilMachineHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_apil_per_machine_calls",
		Help: "Number of calls for each machine.",
	},
	[]string{"machine", "route", "method"},
)

/*hits per bouncer*/
var ApilBouncerHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_apil_per_bouncer_calls",
		Help: "Number of calls for each bouncer.",
	},
	[]string{"bouncer", "route", "method"},
)

/* keep track of the number of calls (per bouncer) that lead to nil/non-nil responses.
while it's not exact, it's a good way to know - when you have a rutpure bouncer - what is the rate of ok/ko answers you got from lapi*/
var ApilNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_apil_decision_nil",
		Help: "Number of calls to /decisions that returned nil result.",
	},
	[]string{"bouncer"},
)

/*hits per bouncer*/
var ApilNonNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_apil_decision_nil",
		Help: "Number of calls to /decisions that returned non-nil result.",
	},
	[]string{"bouncer"},
)

func PrometheusMachinesMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		if claims != nil {
			if rawID, ok := claims["id"]; ok {
				machineID := rawID.(string)
				ApilMachineHits.With(prometheus.Labels{
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
			ApilBouncerHits.With(prometheus.Labels{
				"bouncer": name.(string),
				"route":   c.Request.URL.Path,
				"method":  c.Request.Method}).Inc()
		}
		c.Next()
	}
}

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ApilRouteHits.With(prometheus.Labels{
			"route":  c.Request.URL.Path,
			"method": c.Request.Method}).Inc()
		c.Next()
	}
}
