package apiserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	keyLength = 32
)

type APIServer struct {
	URL            string
	TLS            *csconfig.TLSCfg
	dbClient       *database.Client
	logFile        string
	ctx            context.Context
	middlewares    *middlewares.Middlewares
	controller     *controllers.Controller
	flushScheduler *gocron.Scheduler
}

func NewServer(config *csconfig.LocalApiServerCfg) (*APIServer, error) {
	dbClient, err := database.NewClient(config.DbConfig)
	if err != nil {
		return &APIServer{}, fmt.Errorf("unable to init database client: %s", err)
	}

	middleware, err := middlewares.NewMiddlewares(dbClient)
	if err != nil {
		return &APIServer{}, err
	}
	ctx := context.Background()

	controller := controllers.New(ctx, dbClient, middleware.APIKey.HeaderName)

	flushScheduler, err := dbClient.StartFlushScheduler(config.DbConfig.Flush)
	if err != nil {
		return &APIServer{}, err
	}

	return &APIServer{
		URL:            config.ListenURI,
		TLS:            config.TLS,
		logFile:        fmt.Sprintf("%s/api.log", config.LogDir),
		dbClient:       dbClient,
		middlewares:    middleware,
		controller:     controller,
		flushScheduler: flushScheduler,
	}, nil

}

func (s *APIServer) Router() (*gin.Engine, error) {
	log.Printf("starting router, logging to %s", s.logFile)
	router := gin.New()

	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return nil, errors.Wrap(err, "while configuring gin logger")
	}

	gin.DefaultErrorWriter = clog.Writer()
	router.Use(gin.Recovery())

	router.POST("/watchers", s.controller.CreateMachine)

	router.POST("/watchers/login", s.middlewares.JWT.Middleware.LoginHandler)
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Page or Method not found"})
		return
	})

	jwtAuth := router.Group("/")
	jwtAuth.GET("/refresh_token", s.middlewares.JWT.Middleware.RefreshHandler)
	jwtAuth.Use(s.middlewares.JWT.Middleware.MiddlewareFunc())
	{
		jwtAuth.POST("/alerts", s.controller.CreateAlert)
		jwtAuth.GET("/alerts", s.controller.FindAlerts)
		jwtAuth.DELETE("/alerts", s.controller.DeleteAlerts)
		jwtAuth.DELETE("/decisions", s.controller.DeleteDecisions)
		jwtAuth.DELETE("/decisions/:decision_id", s.controller.DeleteDecisionById)
	}

	apiKeyAuth := router.Group("/")
	apiKeyAuth.Use(s.middlewares.APIKey.MiddlewareFunc())
	{
		apiKeyAuth.GET("/decisions", s.controller.GetDecision)
		apiKeyAuth.GET("/decisions/stream", s.controller.StreamDecision)
	}

	/*puller, err := NewPuller(s.dbClient)
	if err != nil {
		return err
	}

	go puller.Pull()
	*/
	return router, nil
}

func (s *APIServer) Run() error {
	router, err := s.Router()
	if err != nil {
		return err
	}
	if err := router.Run(s.URL); err != nil {
		return err
	}
	return nil
}

func (s *APIServer) Close() {
	s.dbClient.Ent.Close()
	s.flushScheduler.Stop()
}
