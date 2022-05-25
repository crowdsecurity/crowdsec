package apiserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/tomb.v2"
)

var (
	keyLength = 32
)

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
	httpServerTomb tomb.Tomb
	consoleConfig  *csconfig.ConsoleConfig
}

// RecoveryWithWriter returns a middleware for a given writer that recovers from any panics and writes a 500 if there was one.
func CustomRecoveryWithWriter() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Check for a broken connection, as it is not really a
				// condition that warrants a panic stack trace.
				var brokenPipe bool
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
					if strErr == errClientDisconnected ||
						strErr == errClosedBody ||
						strErr == errHandlerComplete ||
						strErr == errStreamClosed {
						brokenPipe = true
					}
				}

				if brokenPipe {
					log.Warningf("client %s disconnected : %s", c.ClientIP(), err)
					c.Abort()
				} else {
					filename := types.WriteStackTrace(err)
					log.Warningf("client %s error : %s", c.ClientIP(), err)
					log.Warningf("stacktrace written to %s, please join to your issue", filename)
					c.AbortWithStatus(http.StatusInternalServerError)
				}
			}
		}()
		c.Next()
	}
}

func NewServer(config *csconfig.LocalApiServerCfg) (*APIServer, error) {
	var flushScheduler *gocron.Scheduler
	dbClient, err := database.NewClient(config.DbConfig)
	if err != nil {
		return &APIServer{}, errors.Wrap(err, "unable to init database client")
	}

	if config.DbConfig.Flush != nil {
		flushScheduler, err = dbClient.StartFlushScheduler(config.DbConfig.Flush)
		if err != nil {
			return &APIServer{}, err
		}
	}

	logFile := ""
	if config.LogMedia == "file" {
		logFile = fmt.Sprintf("%s/crowdsec_api.log", config.LogDir)
	}

	if log.GetLevel() < log.DebugLevel {
		gin.SetMode(gin.ReleaseMode)
	}
	log.Debugf("starting router, logging to %s", logFile)
	router := gin.New()

	if config.TrustedProxies != nil && config.UseForwardedForHeaders {
		if err := router.SetTrustedProxies(*config.TrustedProxies); err != nil {
			return &APIServer{}, errors.Wrap(err, "while setting trusted_proxies")
		}
		router.ForwardedByClientIP = true
	} else {
		router.ForwardedByClientIP = false
	}

	/*The logger that will be used by handlers*/
	clog := log.New()

	if err := types.ConfigureLogger(clog); err != nil {
		return nil, errors.Wrap(err, "while configuring gin logger")
	}
	if config.LogLevel != nil {
		clog.SetLevel(*config.LogLevel)
	}

	/*Configure logs*/
	if logFile != "" {
		_maxsize := 500
		if config.LogMaxSize != 0 {
			_maxsize = config.LogMaxSize
		}
		_maxfiles := 3
		if config.LogMaxFiles != 0 {
			_maxfiles = config.LogMaxFiles
		}
		_maxage := 28
		if config.LogMaxAge != 0 {
			_maxage = config.LogMaxAge
		}
		_compress := true
		if config.CompressLogs != nil {
			_compress = *config.CompressLogs
		}
		/*cf. https://github.com/natefinch/lumberjack/issues/82
		let's create the file beforehand w/ the right perms */
		// check if file exists
		_, err := os.Stat(logFile)
		// create file if not exists, purposefully ignore errors
		if os.IsNotExist(err) {
			file, _ := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE, 0600)
			file.Close()
		}
		LogOutput := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    _maxsize, //megabytes
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,   //days
			Compress:   _compress, //disabled by default
		}
		clog.SetOutput(LogOutput)
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
		DBClient:      dbClient,
		Ectx:          context.Background(),
		Router:        router,
		Profiles:      config.Profiles,
		Log:           clog,
		ConsoleConfig: config.ConsoleConfig,
	}

	var apiClient *apic

	if config.OnlineClient != nil && config.OnlineClient.Credentials != nil {
		log.Printf("Loading CAPI pusher")
		apiClient, err = NewAPIC(config.OnlineClient, dbClient, config.ConsoleConfig)
		if err != nil {
			return &APIServer{}, err
		}
		controller.CAPIChan = apiClient.alertToPush
	} else {
		apiClient = nil
		controller.CAPIChan = nil
	}
	if trustedIPs, err := config.GetTrustedIPs(); err == nil {
		controller.TrustedIPs = trustedIPs
	} else {
		return &APIServer{}, err
	}

	return &APIServer{
		URL:            config.ListenURI,
		TLS:            config.TLS,
		logFile:        logFile,
		dbClient:       dbClient,
		controller:     controller,
		flushScheduler: flushScheduler,
		router:         router,
		apic:           apiClient,
		httpServerTomb: tomb.Tomb{},
		consoleConfig:  config.ConsoleConfig,
	}, nil

}

func (s *APIServer) Router() (*gin.Engine, error) {
	return s.router, nil
}

func (s *APIServer) Run() error {
	defer types.CatchPanic("lapi/runServer")

	s.httpServer = &http.Server{
		Addr:    s.URL,
		Handler: s.router,
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
		s.apic.metricsTomb.Go(func() error {
			if err := s.apic.SendMetrics(); err != nil {
				log.Errorf("capi metrics: %s", err)
				return err
			}
			return nil
		})
	}

	s.httpServerTomb.Go(func() error {
		go func() {
			if s.TLS != nil && s.TLS.CertFilePath != "" && s.TLS.KeyFilePath != "" {
				if err := s.httpServer.ListenAndServeTLS(s.TLS.CertFilePath, s.TLS.KeyFilePath); err != nil {
					log.Fatalf(err.Error())
				}
			} else {
				if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
					log.Fatalf(err.Error())
				}
			}
		}()
		<-s.httpServerTomb.Dying()
		return nil
	})

	return nil
}

func (s *APIServer) Close() {
	if s.apic != nil {
		s.apic.Shutdown() // stop apic first since it use dbClient
	}
	s.dbClient.Ent.Close()
	if s.flushScheduler != nil {
		s.flushScheduler.Stop()
	}
}

func (s *APIServer) Shutdown() error {
	s.Close()
	if err := s.httpServer.Shutdown(context.TODO()); err != nil {
		return err
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
		return errors.Wrap(err, "while waiting on httpServerTomb")
	}
	return nil
}

func (s *APIServer) AttachPluginBroker(broker *csplugin.PluginBroker) {
	s.controller.PluginChannel = broker.PluginChannel
}

func (s *APIServer) InitController() error {
	err := s.controller.Init()
	return err
}
