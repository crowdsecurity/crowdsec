package apiserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
	ctx            context.Context
	controller     *controllers.Controller
	flushScheduler *gocron.Scheduler
	router         *gin.Engine
	httpServer     *http.Server
	apic           *apic
	httpServerTomb tomb.Tomb
}

func NewServer(config *csconfig.LocalApiServerCfg) (*APIServer, error) {
	var flushScheduler *gocron.Scheduler
	dbClient, err := database.NewClient(config.DbConfig)
	if err != nil {
		return &APIServer{}, fmt.Errorf("unable to init database client: %s", err)
	}

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

	log.Debugf("starting router, logging to %s", logFile)
	router := gin.New()

	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return nil, errors.Wrap(err, "while configuring gin logger")
	}
	gin.DefaultErrorWriter = clog.Writer()

	// Logging to a file.
	if logFile != "" {
		file, err := os.Create(logFile)
		if err != nil {
			return &APIServer{}, errors.Wrapf(err, "creating api access log file: %s", logFile)
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

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Page or Method not found"})
		return
	})
	router.Use(gin.Recovery())

	controller := &controllers.Controller{
		DBClient: dbClient,
		Ectx:     context.Background(),
		Router:   router,
		Profiles: config.Profiles,
	}

	if err := controller.Init(); err != nil {
		return &APIServer{}, err
	}
	var apiClient *apic
	if config.OnlineClient != nil {
		apiClient, err = NewAPIC(config.OnlineClient, dbClient)
		if err != nil {
			return &APIServer{}, err
		}
	} else {
		apiClient = nil
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
	}, nil

}

func (s *APIServer) Router() (*gin.Engine, error) {
	return s.router, nil
}

func (s *APIServer) Run() error {
	defer types.CatchPanic("apil/runServer")

	s.httpServer = &http.Server{
		Addr:    s.URL,
		Handler: s.router,
	}

	if s.apic != nil {
		s.apic.pushTomb.Go(func() error {
			if err := s.apic.Push(); err != nil {
				return err
			}
			return nil
		})
		s.apic.pullTomb.Go(func() error {
			if err := s.apic.Pull(); err != nil {
				return err
			}
			return nil
		})
		s.apic.metricsTomb.Go(func() error {
			if err := s.apic.SendMetrics(); err != nil {
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
		if err := s.Shutdown(); err != nil {
			return err
		}
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
	if err := s.httpServer.Shutdown(nil); err != nil {
		return err
	}
	return nil
}
