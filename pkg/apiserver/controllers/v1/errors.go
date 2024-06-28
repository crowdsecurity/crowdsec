package v1

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func (c *Controller) HandleDBErrors(gctx *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ItemNotFound):
		gctx.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.UserExists):
		gctx.JSON(http.StatusForbidden, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.HashError):
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.InsertFail):
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.QueryFail):
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.ParseTimeFail):
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	case errors.Is(err, database.ParseDurationFail):
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	default:
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
}
