package controllers

import (
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
)

func (c *Controller) CreateMachine(gctx *gin.Context) {
	var input models.WatcherRegistrationRequest
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	_, err := c.DBClient.CreateMachine(input.MachineID, input.Password, gctx.ClientIP())
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	gctx.Status(http.StatusOK)
	return
}
