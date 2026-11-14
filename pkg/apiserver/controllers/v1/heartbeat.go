package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func (c *Controller) HeartBeat(gctx *gin.Context) {
	machineID, _ := getMachineIDFromContext(gctx)

	ctx := gctx.Request.Context()

	if err := c.DBClient.UpdateMachineLastHeartBeat(ctx, machineID); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	metrics.GlobalMachinesLastHeartbeatTimestamp.With(prometheus.Labels{"machine": machineID}).SetToCurrentTime()

	gctx.Status(http.StatusOK)
}
