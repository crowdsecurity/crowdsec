package v1

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/gin-gonic/gin"
)

var (
	bouncerContextKey = "bouncer_info"
)

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
