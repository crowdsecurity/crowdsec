package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (c *Controller) GetScenarios(gctx *gin.Context) {
	ctx := gctx.Request.Context()

	scenarios, err := c.DBClient.FetchScenariosListFromDB(ctx)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	gctx.JSON(http.StatusOK, scenarios)
}
