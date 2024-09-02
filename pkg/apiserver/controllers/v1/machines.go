package v1

import (
	"errors"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func (c *Controller) shouldAutoRegister(token string, gctx *gin.Context) (bool, error) {

	if !*c.AutoRegisterCfg.Enable {
		return false, nil
	}

	clientIP := net.ParseIP(gctx.ClientIP())

	//Can probaby happen if using unix socket ?
	if clientIP == nil {
		return false, nil
	}

	//If we have a token, try to perform auto registration
	if token != "" && c.AutoRegisterCfg != nil {
		if token != c.AutoRegisterCfg.Token {
			return false, errors.New("invalid token for auto registration")
		}

		found := false

		for _, ipRange := range c.AutoRegisterCfg.AllowedRangesParsed {
			if ipRange.Contains(clientIP) {
				found = true
				break
			}
		}

		if found {
			return true, nil
		}
		return false, errors.New("IP not in allowed range for auto registration")
	}
	return false, nil
}

func (c *Controller) CreateMachine(gctx *gin.Context) {
	var input models.WatcherRegistrationRequest

	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	if err := input.Validate(strfmt.Default); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	autoRegister, err := c.shouldAutoRegister(input.RegistrationToken, gctx)

	if err != nil {
		log.WithFields(log.Fields{"ip": gctx.ClientIP(), "machine_id": *input.MachineID}).Errorf("Auto-register failed: %s", err)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}

	if _, err := c.DBClient.CreateMachine(input.MachineID, input.Password, gctx.ClientIP(), autoRegister, false, types.PasswordAuthType); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	if autoRegister {
		log.WithFields(log.Fields{"ip": gctx.ClientIP(), "machine_id": *input.MachineID}).Info("Auto-registered machine")
		gctx.Status(http.StatusAccepted)
	} else {
		gctx.Status(http.StatusCreated)
	}
}
