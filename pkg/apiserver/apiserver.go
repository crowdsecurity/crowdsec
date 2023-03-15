package apiserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	v1 "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"
	"github.com/golang-jwt/jwt/v4"
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
	papi           *Papi
	httpServerTomb tomb.Tomb
	consoleConfig  *csconfig.ConsoleConfig
	isEnrolled     bool
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
		DBClient:                      dbClient,
		Ectx:                          context.Background(),
		Router:                        router,
		Profiles:                      config.Profiles,
		Log:                           clog,
		ConsoleConfig:                 config.ConsoleConfig,
		DisableRemoteLapiRegistration: config.DisableRemoteLapiRegistration,
	}

	var apiClient *apic
	var papiClient *Papi
	var isMachineEnrolled = false

	if config.OnlineClient != nil && config.OnlineClient.Credentials != nil {
		log.Printf("Loading CAPI manager")
		apiClient, err = NewAPIC(config.OnlineClient, dbClient, config.ConsoleConfig)
		if err != nil {
			return &APIServer{}, err
		}
		log.Infof("CAPI manager configured successfully")
		isMachineEnrolled = isEnrolled(apiClient.apiClient)
		controller.AlertsAddChan = apiClient.AlertsAddChan
		if fflag.PapiClient.IsEnabled() {
			if isMachineEnrolled {
				log.Infof("Machine is enrolled in the console, Loading PAPI Client")
				papiClient, err = NewPAPI(apiClient, dbClient, config.ConsoleConfig, *config.PapiLogLevel)
				if err != nil {
					return &APIServer{}, err
				}
				controller.DecisionDeleteChan = papiClient.Channels.DeleteDecisionChannel
			} else {
				log.Errorf("Machine is not enrolled in the console, can't synchronize with the console")
			}
		}
	} else {
		apiClient = nil
		controller.AlertsAddChan = nil
		controller.DecisionDeleteChan = nil
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
		papi:           papiClient,
		httpServerTomb: tomb.Tomb{},
		consoleConfig:  config.ConsoleConfig,
		isEnrolled:     isMachineEnrolled,
	}, nil

}

func isEnrolled(client *apiclient.ApiClient) bool {
	apiHTTPClient := client.GetClient()
	jwtTransport := apiHTTPClient.Transport.(*apiclient.JWTTransport)
	tokenStr := jwtTransport.Token

	token, _ := jwt.Parse(tokenStr, nil)
	if token == nil {
		return false
	}
	claims := token.Claims.(jwt.MapClaims)
	_, ok := claims["organization_id"]

	return ok
}

func (s *APIServer) Router() (*gin.Engine, error) {
	return s.router, nil
}

func (s *APIServer) GetTLSConfig() (*tls.Config, error) {
	var caCert []byte
	var err error
	var caCertPool *x509.CertPool
	var clientAuthType tls.ClientAuthType

	if s.TLS == nil {
		return &tls.Config{}, nil
	}

	if s.TLS.ClientVerification == "" {
		//sounds like a sane default : verify client cert if given, but don't make it mandatory
		clientAuthType = tls.VerifyClientCertIfGiven
	} else {
		clientAuthType, err = getTLSAuthType(s.TLS.ClientVerification)
		if err != nil {
			return nil, err
		}
	}

	if s.TLS.CACertPath != "" {
		if clientAuthType > tls.RequestClientCert {
			log.Infof("(tls) Client Auth Type set to %s", clientAuthType.String())
			caCert, err = os.ReadFile(s.TLS.CACertPath)
			if err != nil {
				return nil, errors.Wrap(err, "Error opening cert file")
			}
			caCertPool = x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
		}
	}

	return &tls.Config{
		ServerName: s.TLS.ServerName, //should it be removed ?
		ClientAuth: clientAuthType,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12, // TLS versions below 1.2 are considered insecure - see https://www.rfc-editor.org/rfc/rfc7525.txt for details
	}, nil
}

func (s *APIServer) Run(apiReady chan bool) error {
	defer types.CatchPanic("lapi/runServer")
	tlsCfg, err := s.GetTLSConfig()
	if err != nil {
		return errors.Wrap(err, "while creating TLS config")
	}
	s.httpServer = &http.Server{
		Addr:      s.URL,
		Handler:   s.router,
		TLSConfig: tlsCfg,
	}

	s.httpServerTomb.Go(func() error {
		go func() {
			apiReady <- true
			log.Infof("CrowdSec Local API listening on %s", s.URL)
			if s.TLS != nil && (s.TLS.CertFilePath != "" || s.TLS.KeyFilePath != "") {
				if s.TLS.KeyFilePath == "" {
					log.Fatalf("while serving local API: %v", errors.New("missing TLS key file"))
				} else if s.TLS.CertFilePath == "" {
					log.Fatalf("while serving local API: %v", errors.New("missing TLS cert file"))
				}

				if err := s.httpServer.ListenAndServeTLS(s.TLS.CertFilePath, s.TLS.KeyFilePath); err != nil {
					log.Fatalf("while serving local API: %v", err)
				}
			} else {
				if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
					log.Fatalf("while serving local API: %v", err)
				}
			}
		}()
		<-s.httpServerTomb.Dying()
		return nil
	})

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
			if fflag.PapiClient.IsEnabled() {
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
		}

		s.apic.metricsTomb.Go(func() error {
			s.apic.SendMetrics(make(chan bool))
			return nil
		})
	}

	return nil
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
		return errors.Wrap(err, "while waiting on httpServerTomb")
	}
	return nil
}

func (s *APIServer) AttachPluginBroker(broker *csplugin.PluginBroker) {
	s.controller.PluginChannel = broker.PluginChannel
}

func (s *APIServer) InitController() error {

	err := s.controller.Init()
	if err != nil {
		return errors.Wrap(err, "controller init")
	}
	if s.TLS != nil {
		var cacheExpiration time.Duration
		if s.TLS.CacheExpiration != nil {
			cacheExpiration = *s.TLS.CacheExpiration
		} else {
			cacheExpiration = time.Hour
		}
		s.controller.HandlerV1.Middlewares.JWT.TlsAuth, err = v1.NewTLSAuth(s.TLS.AllowedAgentsOU, s.TLS.CRLPath,
			cacheExpiration,
			log.WithFields(log.Fields{
				"component": "tls-auth",
				"type":      "agent",
			}))
		if err != nil {
			return errors.Wrap(err, "while creating TLS auth for agents")
		}
		s.controller.HandlerV1.Middlewares.APIKey.TlsAuth, err = v1.NewTLSAuth(s.TLS.AllowedBouncersOU, s.TLS.CRLPath,
			cacheExpiration,
			log.WithFields(log.Fields{
				"component": "tls-auth",
				"type":      "bouncer",
			}))
		if err != nil {
			return errors.Wrap(err, "while creating TLS auth for bouncers")
		}
	}
	return err
}
