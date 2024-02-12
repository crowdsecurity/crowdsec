package v1

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

const bouncerContextKey = "bouncer_info"

func getBouncerFromContext(ctx *gin.Context) (*ent.Bouncer, error) {
	bouncerInterface, exist := ctx.Get(bouncerContextKey)
	if !exist {
		return nil, fmt.Errorf("bouncer not found")
	}

	bouncerInfo, ok := bouncerInterface.(*ent.Bouncer)
	if !ok {
		return nil, fmt.Errorf("bouncer not found")
	}

	return bouncerInfo, nil
}

func isUnixSocket(c *gin.Context) bool {
	if localAddr, ok := c.Request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return strings.HasPrefix(localAddr.Network(), "unix")
	}

	return false
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
