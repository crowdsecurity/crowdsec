package controllers

import (
	"context"

	v1 "github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	Ectx     context.Context
	DBClient *database.Client
	Router   *gin.Engine
	Profiles []*csconfig.ProfileCfg
	CAPIChan chan []*models.Alert
	Log      *log.Logger
}

func (c *Controller) Init() error {
	if err := c.NewV1(); err != nil {
		return err
	}

	/* if we have a V2, just add

	if err := c.NewV2(); err != nil {
		return err
	}

	*/

	return nil
}

func (c *Controller) NewV1() error {
	handlerV1, err := v1.New(c.DBClient, c.Ectx, c.Profiles, c.CAPIChan)
	if err != nil {
		return err
	}

	c.Router.Use(v1.PrometheusMiddleware())
	v1 := c.Router.Group("/v1")
	v1.POST("/watchers", handlerV1.CreateMachine)
	v1.POST("/watchers/login", handlerV1.Middlewares.JWT.Middleware.LoginHandler)

	jwtAuth := v1.Group("")
	jwtAuth.GET("/refresh_token", handlerV1.Middlewares.JWT.Middleware.RefreshHandler)
	jwtAuth.Use(handlerV1.Middlewares.JWT.Middleware.MiddlewareFunc())
	{
		jwtAuth.POST("/alerts", handlerV1.CreateAlert)
		jwtAuth.GET("/alerts", handlerV1.FindAlerts)
		jwtAuth.GET("/alerts/:alert_id", handlerV1.FindAlertByID)
		jwtAuth.DELETE("/alerts", handlerV1.DeleteAlerts)
		jwtAuth.DELETE("/decisions", handlerV1.DeleteDecisions)
		jwtAuth.DELETE("/decisions/:decision_id", handlerV1.DeleteDecisionById)
	}

	apiKeyAuth := v1.Group("")
	apiKeyAuth.Use(handlerV1.Middlewares.APIKey.MiddlewareFunc())
	{
		apiKeyAuth.GET("/decisions", handlerV1.GetDecision)
		apiKeyAuth.GET("/decisions/stream", handlerV1.StreamDecision)
	}

	return nil
}

/*
func (c *Controller) NewV2() error {
	handlerV2, err := v2.New(c.DBClient, c.Ectx)
	if err != nil {
		return err
	}

	v2 := c.Router.Group("/v2")
	v2.POST("/watchers", handlerV2.CreateMachine)
	v2.POST("/watchers/login", handlerV2.Middlewares.JWT.Middleware.LoginHandler)

	jwtAuth := v2.Group("")
	jwtAuth.GET("/refresh_token", handlerV2.Middlewares.JWT.Middleware.RefreshHandler)
	jwtAuth.Use(handlerV2.Middlewares.JWT.Middleware.MiddlewareFunc())
	{
		jwtAuth.POST("/alerts", handlerV2.CreateAlert)
		jwtAuth.GET("/alerts", handlerV2.FindAlerts)
		jwtAuth.DELETE("/alerts", handlerV2.DeleteAlerts)
		jwtAuth.DELETE("/decisions", handlerV2.DeleteDecisions)
		jwtAuth.DELETE("/decisions/:decision_id", handlerV2.DeleteDecisionById)
	}

	apiKeyAuth := v2.Group("")
	apiKeyAuth.Use(handlerV2.Middlewares.APIKey.MiddlewareFuncV2())
	{
		apiKeyAuth.GET("/decisions", handlerV2.GetDecision)
		apiKeyAuth.GET("/decisions/stream", handlerV2.StreamDecision)
	}

	return nil
}

*/
