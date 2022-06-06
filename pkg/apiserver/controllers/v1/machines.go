package v1

import (
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
)

func (c *Controller) CreateMachine(gctx *gin.Context) {
	var err error
	var input models.WatcherRegistrationRequest
	if err = gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	if err = input.Validate(strfmt.Default); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	_, err = c.DBClient.CreateMachine(input.MachineID, input.Password, gctx.ClientIP(), false, false)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	gctx.Status(http.StatusCreated)
}
