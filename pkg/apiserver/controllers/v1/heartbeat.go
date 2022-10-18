package v1

import (
	"net/http"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

func (c *Controller) HeartBeat(gctx *gin.Context) {

	claims := jwt.ExtractClaims(gctx)
	// TBD: use defined rather than hardcoded key to find back owner
	machineID := claims["id"].(string)

	if err := c.DBClient.UpdateMachineLastHeartBeat(machineID); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}
	gctx.Status(http.StatusOK)
}
