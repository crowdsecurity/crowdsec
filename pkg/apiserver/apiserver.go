package apiserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	v1 "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const keyLength = 32

type APIServer struct {
	URL            string
	TLS            *csconfig.TLSCfg
	dbClient       *database.Client
	logFile        string
	controller     *controllers.Controller
	flushScheduler *gocron.Scheduler
	router         *gin.Engine
	httpServer     *http.Server
	apic           *apic
	papi           *Papi
	httpServerTomb tomb.Tomb
	consoleConfig  *csconfig.ConsoleConfig
	isEnrolled     bool
}

func recoverFromPanic(c *gin.Context) {
	err := recover()
	if err == nil {
		return
	}

	// Check for a broken connection, as it is not really a
	// condition that warrants a panic stack trace.
	brokenPipe := false

	if ne, ok := err.(*net.OpError); ok {
		if se, ok := ne.Err.(*os.SyscallError); ok {
			if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
				brokenPipe = true
			}
		}
	}

	// because of https://github.com/golang/net/blob/39120d07d75e76f0079fe5d27480bcb965a21e4c/http2/server.go
	// and because it seems gin doesn't handle those neither, we need to "hand define" some errors to properly catch them
	if strErr, ok := err.(error); ok {
		//stolen from http2/server.go in x/net
		var (
			errClientDisconnected = errors.New("client disconnected")
			errClosedBody         = errors.New("body closed by handler")
			errHandlerComplete    = errors.New("http2: request body closed due to handler exiting")
			errStreamClosed       = errors.New("http2: stream closed")
		)

		if errors.Is(strErr, errClientDisconnected) ||
			errors.Is(strErr, errClosedBody) ||
			errors.Is(strErr, errHandlerComplete) ||
			errors.Is(strErr, errStreamClosed) {
			brokenPipe = true
		}
	}

	if brokenPipe {
		log.Warningf("client %s disconnected : %s", c.ClientIP(), err)
		c.Abort()
	} else {
		filename := trace.WriteStackTrace(err)
		log.Warningf("client %s error : %s", c.ClientIP(), err)
		log.Warningf("stacktrace written to %s, please join to your issue", filename)
		c.AbortWithStatus(http.StatusInternalServerError)
	}
}

// CustomRecoveryWithWriter returns a middleware for a writer that recovers from any panics and writes a 500 if there was one.
func CustomRecoveryWithWriter() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer recoverFromPanic(c)
		c.Next()
	}
}

// XXX: could be a method of LocalApiServerCfg
func newGinLogger(config *csconfig.LocalApiServerCfg) (*log.Logger, string, error) {
	clog := log.New()

	if err := types.ConfigureLogger(clog); err != nil {
		return nil, "", fmt.Errorf("while configuring gin logger: %w", err)
	}

	if config.LogLevel != nil {
		clog.SetLevel(*config.LogLevel)
	}

	if config.LogMedia != "file" {
		return clog, "", nil
	}

	// Log rotation

	logFile := filepath.Join(config.LogDir, "crowdsec_api.log")
	log.Debugf("starting router, logging to %s", logFile)

	logger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    500, //megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, //disabled by default
	}

	if config.LogMaxSize != 0 {
		logger.MaxSize = config.LogMaxSize
	}

	if config.LogMaxFiles != 0 {
		logger.MaxBackups = config.LogMaxFiles
	}

	if config.LogMaxAge != 0 {
		logger.MaxAge = config.LogMaxAge
	}

	if config.CompressLogs != nil {
		logger.Compress = *config.CompressLogs
	}

	clog.SetOutput(logger)

	return clog, logFile, nil
}

// NewServer creates a LAPI server.
// It sets up a gin router, a database client, and a controller.
func NewServer(config *csconfig.LocalApiServerCfg) (*APIServer, error) {
	var flushScheduler *gocron.Scheduler

	dbClient, err := database.NewClient(config.DbConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to init database client: %w", err)
	}

	if config.DbConfig.Flush != nil {
		flushScheduler, err = dbClient.StartFlushScheduler(config.DbConfig.Flush)
		if err != nil {
			return nil, err
		}
	}

	if log.GetLevel() < log.DebugLevel {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	router.ForwardedByClientIP = false

	if config.TrustedProxies != nil && config.UseForwardedForHeaders {
		if err = router.SetTrustedProxies(*config.TrustedProxies); err != nil {
			return nil, fmt.Errorf("while setting trusted_proxies: %w", err)
		}

		router.ForwardedByClientIP = true
	}

	// The logger that will be used by handlers
	clog, logFile, err := newGinLogger(config)
	if err != nil {
		return nil, err
	}

	gin.DefaultErrorWriter = clog.WriterLevel(log.ErrorLevel)
	gin.DefaultWriter = clog.Writer()

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

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Page or Method not found"})
	})
	router.Use(CustomRecoveryWithWriter())

	controller := &controllers.Controller{
		DBClient:                      dbClient,
		Ectx:                          context.Background(),
		Router:                        router,
		Profiles:                      config.Profiles,
		Log:                           clog,
		ConsoleConfig:                 config.ConsoleConfig,
		DisableRemoteLapiRegistration: config.DisableRemoteLapiRegistration,
	}

	var (
		apiClient         *apic
		papiClient        *Papi
		isMachineEnrolled = false
	)

	controller.AlertsAddChan = nil
	controller.DecisionDeleteChan = nil

	if config.OnlineClient != nil && config.OnlineClient.Credentials != nil {
		log.Printf("Loading CAPI manager")

		apiClient, err = NewAPIC(config.OnlineClient, dbClient, config.ConsoleConfig, config.CapiWhitelists)
		if err != nil {
			return nil, err
		}

		log.Infof("CAPI manager configured successfully")

		controller.AlertsAddChan = apiClient.AlertsAddChan

		if apiClient.apiClient.IsEnrolled() {
			isMachineEnrolled = true

			log.Infof("Machine is enrolled in the console, Loading PAPI Client")

			papiClient, err = NewPAPI(apiClient, dbClient, config.ConsoleConfig, *config.PapiLogLevel)
			if err != nil {
				return nil, err
			}

			controller.DecisionDeleteChan = papiClient.Channels.DeleteDecisionChannel
		} else {
			log.Errorf("Machine is not enrolled in the console, can't synchronize with the console")
		}
	}

	trustedIPs, err := config.GetTrustedIPs()
	if err != nil {
		return nil, err
	}

	controller.TrustedIPs = trustedIPs

	return &APIServer{
		URL:            config.ListenURI,
		TLS:            config.TLS,
		logFile:        logFile,
		dbClient:       dbClient,
		controller:     controller,
		flushScheduler: flushScheduler,
		router:         router,
		apic:           apiClient,
		papi:           papiClient,
		httpServerTomb: tomb.Tomb{},
		consoleConfig:  config.ConsoleConfig,
		isEnrolled:     isMachineEnrolled,
	}, nil
}

func (s *APIServer) Router() (*gin.Engine, error) {
	return s.router, nil
}

func (s *APIServer) Run(apiReady chan bool) error {
	defer trace.CatchPanic("lapi/runServer")

	tlsCfg, err := s.TLS.GetTLSConfig()
	if err != nil {
		return fmt.Errorf("while creating TLS config: %w", err)
	}

	s.httpServer = &http.Server{
		Addr:      s.URL,
		Handler:   s.router,
		TLSConfig: tlsCfg,
	}

	if s.apic != nil {
		s.apic.pushTomb.Go(func() error {
			if err := s.apic.Push(); err != nil {
				log.Errorf("capi push: %s", err)
				return err
			}
			return nil
		})

		s.apic.pullTomb.Go(func() error {
			if err := s.apic.Pull(); err != nil {
				log.Errorf("capi pull: %s", err)
				return err
			}
			return nil
		})

		//csConfig.API.Server.ConsoleConfig.ShareCustomScenarios
		if s.isEnrolled {
			if s.consoleConfig.ConsoleManagement != nil && *s.consoleConfig.ConsoleManagement {
				if s.papi.URL != "" {
					log.Infof("Starting PAPI decision receiver")
					s.papi.pullTomb.Go(func() error {
						if err := s.papi.Pull(); err != nil {
							log.Errorf("papi pull: %s", err)
							return err
						}
						return nil
					})

					s.papi.syncTomb.Go(func() error {
						if err := s.papi.SyncDecisions(); err != nil {
							log.Errorf("capi decisions sync: %s", err)
							return err
						}
						return nil
					})
				} else {
					log.Warnf("papi_url is not set in online_api_credentials.yaml, can't synchronize with the console. Run cscli console enable console_management to add it.")
				}
			} else {
				log.Warningf("Machine is not allowed to synchronize decisions, you can enable it with `cscli console enable console_management`")
			}
		}

		s.apic.metricsTomb.Go(func() error {
			s.apic.SendMetrics(make(chan bool))
			return nil
		})
	}

	s.httpServerTomb.Go(func() error { s.listenAndServeURL(apiReady); return nil })

	return nil
}

// listenAndServeURL starts the http server and blocks until it's closed
// it also updates the URL field with the actual address the server is listening on
// it's meant to be run in a separate goroutine
func (s *APIServer) listenAndServeURL(apiReady chan bool) {
	serverError := make(chan error, 1)

	go func() {
		listener, err := net.Listen("tcp", s.URL)
		if err != nil {
			serverError <- fmt.Errorf("listening on %s: %w", s.URL, err)
			return
		}

		s.URL = listener.Addr().String()
		log.Infof("CrowdSec Local API listening on %s", s.URL)
		apiReady <- true

		if s.TLS != nil && (s.TLS.CertFilePath != "" || s.TLS.KeyFilePath != "") {
			if s.TLS.KeyFilePath == "" {
				serverError <- errors.New("missing TLS key file")
				return
			} else if s.TLS.CertFilePath == "" {
				serverError <- errors.New("missing TLS cert file")
				return
			}

			err = s.httpServer.ServeTLS(listener, s.TLS.CertFilePath, s.TLS.KeyFilePath)
		} else {
			err = s.httpServer.Serve(listener)
		}

		if err != nil && err != http.ErrServerClosed {
			serverError <- fmt.Errorf("while serving local API: %w", err)
			return
		}
	}()

	select {
	case err := <-serverError:
		log.Fatalf("while starting API server: %s", err)
	case <-s.httpServerTomb.Dying():
		log.Infof("Shutting down API server")
		// do we need a graceful shutdown here?
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Errorf("while shutting down http server: %s", err)
		}
	}
}

func (s *APIServer) Close() {
	if s.apic != nil {
		s.apic.Shutdown() // stop apic first since it use dbClient
	}

	if s.papi != nil {
		s.papi.Shutdown() // papi also uses the dbClient
	}

	s.dbClient.Ent.Close()

	if s.flushScheduler != nil {
		s.flushScheduler.Stop()
	}
}

func (s *APIServer) Shutdown() error {
	s.Close()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(context.TODO()); err != nil {
			return err
		}
	}

	//close io.writer logger given to gin
	if pipe, ok := gin.DefaultErrorWriter.(*io.PipeWriter); ok {
		pipe.Close()
	}

	if pipe, ok := gin.DefaultWriter.(*io.PipeWriter); ok {
		pipe.Close()
	}

	s.httpServerTomb.Kill(nil)

	if err := s.httpServerTomb.Wait(); err != nil {
		return fmt.Errorf("while waiting on httpServerTomb: %w", err)
	}

	return nil
}

func (s *APIServer) AttachPluginBroker(broker *csplugin.PluginBroker) {
	s.controller.PluginChannel = broker.PluginChannel
}

func (s *APIServer) InitController() error {
	err := s.controller.Init()
	if err != nil {
		return fmt.Errorf("controller init: %w", err)
	}

	if s.TLS == nil {
		return nil
	}

	// TLS is configured: create the TLSAuth middleware for agents and bouncers

	cacheExpiration := time.Hour
	if s.TLS.CacheExpiration != nil {
		cacheExpiration = *s.TLS.CacheExpiration
	}

	s.controller.HandlerV1.Middlewares.JWT.TlsAuth, err = v1.NewTLSAuth(s.TLS.AllowedAgentsOU, s.TLS.CRLPath,
		cacheExpiration,
		log.WithFields(log.Fields{
			"component": "tls-auth",
			"type":      "agent",
		}))
	if err != nil {
		return fmt.Errorf("while creating TLS auth for agents: %w", err)
	}

	s.controller.HandlerV1.Middlewares.APIKey.TlsAuth, err = v1.NewTLSAuth(s.TLS.AllowedBouncersOU, s.TLS.CRLPath,
		cacheExpiration,
		log.WithFields(log.Fields{
			"component": "tls-auth",
			"type":      "bouncer",
		}))
	if err != nil {
		return fmt.Errorf("while creating TLS auth for bouncers: %w", err)
	}

	return nil
}
