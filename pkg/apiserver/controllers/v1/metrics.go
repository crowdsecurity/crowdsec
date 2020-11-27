package v1

import (
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

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ApilRouteHits.With(prometheus.Labels{
			"route":  c.Request.URL.Path,
			"method": c.Request.Method}).Inc()
		c.Next()
	}
}
