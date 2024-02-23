package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (c *Controller) HeartBeat(gctx *gin.Context) {
	machineID, _ := getMachineIDFromContext(gctx)

	if err := c.DBClient.UpdateMachineLastHeartBeat(machineID); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	gctx.Status(http.StatusOK)
}
