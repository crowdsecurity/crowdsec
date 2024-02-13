package v1

import (
        "net/http"

        jwt "github.com/appleboy/gin-jwt/v2"
        "github.com/gin-gonic/gin"
//	"github.com/sanity-io/litter"
        "github.com/go-openapi/strfmt"
        log "github.com/sirupsen/logrus"

        "github.com/crowdsecurity/crowdsec/pkg/models"
)

// UsageMetrics receives metrics from log processors and remediation components
func (c *Controller) UsageMetrics(gctx *gin.Context) {
        var input models.AllMetrics

        claims := jwt.ExtractClaims(gctx)
        // TBD: use defined rather than hardcoded key to find back owner
        machineID := claims["id"].(string)

        if err := gctx.ShouldBindJSON(&input); err != nil {
                log.Errorf("Failed to bind json: %s", err)
                gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
                return
        }

        if err := input.Validate(strfmt.Default); err != nil {
                log.Errorf("Failed to validate input: %s", err)
                c.HandleDBErrors(gctx, err)
                return
        }

        log.Infof("Received all metrics from %s", machineID)

	// inputStr := litter.Sdump(input)
	// log.Trace(inputStr)

	// empty body
	gctx.Status(http.StatusCreated)
}
