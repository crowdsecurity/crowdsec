package apiserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

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
	var flushScheduler *gocron.Scheduler
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

	if config.DbConfig.Flush != nil {
		flushScheduler, err = dbClient.StartFlushScheduler(config.DbConfig.Flush)
		if err != nil {
			return &APIServer{}, err
		}
	}

	logFile := ""
	if config.LogDir != "" {
		logFile = fmt.Sprintf("%s/crowdsec_api.log", config.LogDir)
	}

	return &APIServer{
		URL:            config.ListenURI,
		TLS:            config.TLS,
		logFile:        logFile,
		dbClient:       dbClient,
		middlewares:    middleware,
		controller:     controller,
		flushScheduler: flushScheduler,
	}, nil

}

func (s *APIServer) Router() (*gin.Engine, error) {
	log.Debugf("starting router, logging to %s", s.logFile)
	router := gin.New()

	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return nil, errors.Wrap(err, "while configuring gin logger")
	}
	gin.DefaultErrorWriter = clog.Writer()

	// Logging to a file.
	if s.logFile != "" {
		file, err := os.Create(s.logFile)
		if err != nil {
			return &gin.Engine{}, errors.Wrapf(err, "creating api access log file: %s", s.logFile)
		}
		gin.DefaultWriter = io.MultiWriter(file, os.Stdout)
	}

	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))
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
	if s.flushScheduler != nil {
		s.flushScheduler.Stop()
	}
}
