package v1

import (
	"errors"
	"net"
	"net/http"
	"strings"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func getBouncerFromContext(ctx *gin.Context) (*ent.Bouncer, error) {
	bouncerInterface, exist := ctx.Get(middlewares.BouncerContextKey)
	if !exist {
		return nil, errors.New("bouncer not found")
	}

	bouncerInfo, ok := bouncerInterface.(*ent.Bouncer)
	if !ok {
		return nil, errors.New("bouncer not found")
	}

	return bouncerInfo, nil
}

func isUnixSocket(c *gin.Context) bool {
	if localAddr, ok := c.Request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return strings.HasPrefix(localAddr.Network(), "unix")
	}

	return false
}

func getMachineIDFromContext(ctx *gin.Context) (string, error) {
	claims := jwt.ExtractClaims(ctx)
	if claims == nil {
		return "", errors.New("failed to extract claims")
	}

	rawID, ok := claims[middlewares.MachineIDKey]
	if !ok {
		return "", errors.New("MachineID not found in claims")
	}

	id, ok := rawID.(string)
	if !ok {
		// should never happen
		return "", errors.New("failed to cast machineID to string")
	}

	return id, nil
}

func (c *Controller) AbortRemoteIf(option bool) gin.HandlerFunc {
	return func(gctx *gin.Context) {
		if !option {
			return
		}

		if isUnixSocket(gctx) {
			return
		}

		incomingIP := gctx.ClientIP()
		if incomingIP != "127.0.0.1" && incomingIP != "::1" {
			gctx.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			gctx.Abort()
		}
	}
}
