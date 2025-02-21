package appsecacquisition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/allowlists"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	InBand    = "inband"
	OutOfBand = "outofband"
)

var DefaultAuthCacheDuration = (1 * time.Minute)

// configuration structure of the acquis for the application security engine
type AppsecSourceConfig struct {
	ListenAddr                        string         `yaml:"listen_addr"`
	ListenSocket                      string         `yaml:"listen_socket"`
	CertFilePath                      string         `yaml:"cert_file"`
	KeyFilePath                       string         `yaml:"key_file"`
	Path                              string         `yaml:"path"`
	Routines                          int            `yaml:"routines"`
	AppsecConfig                      string         `yaml:"appsec_config"`
	AppsecConfigs                     []string       `yaml:"appsec_configs"`
	AppsecConfigPath                  string         `yaml:"appsec_config_path"`
	AuthCacheDuration                 *time.Duration `yaml:"auth_cache_duration"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

// runtime structure of AppsecSourceConfig
type AppsecSource struct {
	metricsLevel          int
	config                AppsecSourceConfig
	logger                *log.Entry
	mux                   *http.ServeMux
	server                *http.Server
	outChan               chan types.Event
	InChan                chan appsec.ParsedRequest
	AppsecRuntime         *appsec.AppsecRuntimeConfig
	AppsecConfigs         map[string]appsec.AppsecConfig
	lapiURL               string
	AuthCache             AuthCache
	AppsecRunners         []AppsecRunner // one for each go-routine
	apiClient             *apiclient.ApiClient
	appsecAllowlistClient *allowlists.AppsecAllowlist
}

// Struct to handle cache of authentication
type AuthCache struct {
	APIKeys map[string]time.Time
	mu      sync.RWMutex
}

func NewAuthCache() AuthCache {
	return AuthCache{
		APIKeys: make(map[string]time.Time, 0),
		mu:      sync.RWMutex{},
	}
}

func (ac *AuthCache) Set(apiKey string, expiration time.Time) {
	ac.mu.Lock()
	ac.APIKeys[apiKey] = expiration
	ac.mu.Unlock()
}

func (ac *AuthCache) Get(apiKey string) (time.Time, bool) {
	ac.mu.RLock()
	expiration, exists := ac.APIKeys[apiKey]
	ac.mu.RUnlock()

	return expiration, exists
}

// @tko + @sbl : we might want to get rid of that or improve it
type BodyResponse struct {
	Action string `json:"action"`
}

func (w *AppsecSource) UnmarshalConfig(yamlConfig []byte) error {
	err := yaml.UnmarshalStrict(yamlConfig, &w.config)
	if err != nil {
		return fmt.Errorf("cannot parse appsec configuration: %w", err)
	}

	if w.config.ListenAddr == "" && w.config.ListenSocket == "" {
		w.config.ListenAddr = "127.0.0.1:7422"
	}

	if w.config.Path == "" {
		w.config.Path = "/"
	}

	if w.config.Path[0] != '/' {
		w.config.Path = "/" + w.config.Path
	}

	if w.config.Mode == "" {
		w.config.Mode = configuration.TAIL_MODE
	}

	// always have at least one appsec routine
	if w.config.Routines == 0 {
		w.config.Routines = 1
	}

	if w.config.AppsecConfig == "" && w.config.AppsecConfigPath == "" && len(w.config.AppsecConfigs) == 0 {
		return errors.New("appsec_config or appsec_config_path must be set")
	}

	if (w.config.AppsecConfig != "" || w.config.AppsecConfigPath != "") && len(w.config.AppsecConfigs) != 0 {
		return errors.New("appsec_config and appsec_config_path are mutually exclusive with appsec_configs")
	}

	if w.config.Name == "" {
		if w.config.ListenSocket != "" && w.config.ListenAddr == "" {
			w.config.Name = w.config.ListenSocket
		}

		if w.config.ListenSocket == "" {
			w.config.Name = fmt.Sprintf("%s%s", w.config.ListenAddr, w.config.Path)
		}
	}

	csConfig := csconfig.GetConfig()
	w.lapiURL = fmt.Sprintf("%sv1/decisions/stream", csConfig.API.Client.Credentials.URL)
	w.AuthCache = NewAuthCache()

	return nil
}

func (w *AppsecSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{AppsecReqCounter, AppsecBlockCounter, AppsecRuleHits, AppsecOutbandParsingHistogram, AppsecInbandParsingHistogram, AppsecGlobalParsingHistogram}
}

func (w *AppsecSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{AppsecReqCounter, AppsecBlockCounter, AppsecRuleHits, AppsecOutbandParsingHistogram, AppsecInbandParsingHistogram, AppsecGlobalParsingHistogram}
}

func (w *AppsecSource) Configure(yamlConfig []byte, logger *log.Entry, metricsLevel int) error {
	err := w.UnmarshalConfig(yamlConfig)
	if err != nil {
		return fmt.Errorf("unable to parse appsec configuration: %w", err)
	}

	w.logger = logger
	w.metricsLevel = metricsLevel
	w.logger.Tracef("Appsec configuration: %+v", w.config)

	if w.config.AuthCacheDuration == nil {
		w.config.AuthCacheDuration = &DefaultAuthCacheDuration
		w.logger.Infof("Cache duration for auth not set, using default: %v", *w.config.AuthCacheDuration)
	}

	w.mux = http.NewServeMux()

	w.server = &http.Server{
		Addr:      w.config.ListenAddr,
		Handler:   w.mux,
		Protocols: &http.Protocols{},
	}

	w.server.Protocols.SetHTTP1(true)
	w.server.Protocols.SetUnencryptedHTTP2(true)
	w.server.Protocols.SetHTTP2(true)

	w.InChan = make(chan appsec.ParsedRequest)
	appsecCfg := appsec.AppsecConfig{Logger: w.logger.WithField("component", "appsec_config")}

	// we keep the datasource name
	appsecCfg.Name = w.config.Name

	// let's load the associated appsec_config:
	if w.config.AppsecConfigPath != "" {
		if err = appsecCfg.LoadByPath(w.config.AppsecConfigPath); err != nil {
			return fmt.Errorf("unable to load appsec_config: %w", err)
		}
	} else if w.config.AppsecConfig != "" {
		if err = appsecCfg.Load(w.config.AppsecConfig); err != nil {
			return fmt.Errorf("unable to load appsec_config: %w", err)
		}
	} else if len(w.config.AppsecConfigs) > 0 {
		for _, appsecConfig := range w.config.AppsecConfigs {
			if err = appsecCfg.Load(appsecConfig); err != nil {
				return fmt.Errorf("unable to load appsec_config: %w", err)
			}
		}
	} else {
		return errors.New("no appsec_config provided")
	}

	// Now we can set up the logger
	appsecCfg.SetUpLogger()

	w.AppsecRuntime, err = appsecCfg.Build()
	if err != nil {
		return fmt.Errorf("unable to build appsec_config: %w", err)
	}

	err = w.AppsecRuntime.ProcessOnLoadRules()
	if err != nil {
		return fmt.Errorf("unable to process on load rules: %w", err)
	}

	w.AppsecRunners = make([]AppsecRunner, w.config.Routines)

	w.apiClient, err = apiclient.GetLAPIClient()
	if err != nil {
		return fmt.Errorf("unable to get authenticated LAPI client: %w", err)
	}

	w.appsecAllowlistClient = allowlists.NewAppsecAllowlist(w.apiClient, w.logger)

	for nbRoutine := range w.config.Routines {
		appsecRunnerUUID := uuid.New().String()
		// we copy AppsecRuntime for each runner
		wrt := *w.AppsecRuntime
		wrt.Logger = w.logger.Dup().WithField("runner_uuid", appsecRunnerUUID)
		runner := AppsecRunner{
			inChan:                 w.InChan,
			UUID:                   appsecRunnerUUID,
			logger:                 w.logger.WithField("runner_uuid", appsecRunnerUUID),
			AppsecRuntime:          &wrt,
			Labels:                 w.config.Labels,
			appsecAllowlistsClient: w.appsecAllowlistClient,
		}

		err := runner.Init(appsecCfg.GetDataDir())
		if err != nil {
			return fmt.Errorf("unable to initialize runner: %w", err)
		}

		w.AppsecRunners[nbRoutine] = runner
	}

	w.logger.Infof("Created %d appsec runners", len(w.AppsecRunners))

	// We don´t use the wrapper provided by coraza because we want to fully control what happens when a rule match to send the information in crowdsec
	w.mux.HandleFunc(w.config.Path, w.appsecHandler)

	return nil
}

func (w *AppsecSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return errors.New("AppSec datasource does not support command line acquisition")
}

func (w *AppsecSource) GetMode() string {
	return w.config.Mode
}

func (w *AppsecSource) GetName() string {
	return "appsec"
}

func (w *AppsecSource) OneShotAcquisition(_ context.Context, _ chan types.Event, _ *tomb.Tomb) error {
	return errors.New("AppSec datasource does not support command line acquisition")
}

func (w *AppsecSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	w.outChan = out

	w.appsecAllowlistClient.StartRefresh(t)

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/appsec/live")

		w.logger.Infof("%d appsec runner to start", len(w.AppsecRunners))

		for _, runner := range w.AppsecRunners {
			runner.outChan = out

			t.Go(func() error {
				defer trace.CatchPanic("crowdsec/acquis/appsec/live/runner")
				return runner.Run(t)
			})
		}

		t.Go(func() error {
			if w.config.ListenSocket != "" {
				w.logger.Infof("creating unix socket %s", w.config.ListenSocket)
				_ = os.RemoveAll(w.config.ListenSocket)

				listener, err := net.Listen("unix", w.config.ListenSocket)
				if err != nil {
					return fmt.Errorf("appsec server failed: %w", err)
				}

				defer listener.Close()

				if w.config.CertFilePath != "" && w.config.KeyFilePath != "" {
					err = w.server.ServeTLS(listener, w.config.CertFilePath, w.config.KeyFilePath)
				} else {
					err = w.server.Serve(listener)
				}

				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					return fmt.Errorf("appsec server failed: %w", err)
				}
			}

			return nil
		})
		t.Go(func() error {
			var err error

			if w.config.ListenAddr != "" {
				w.logger.Infof("creating TCP server on %s", w.config.ListenAddr)

				if w.config.CertFilePath != "" && w.config.KeyFilePath != "" {
					err = w.server.ListenAndServeTLS(w.config.CertFilePath, w.config.KeyFilePath)
				} else {
					err = w.server.ListenAndServe()
				}

				if err != nil && err != http.ErrServerClosed {
					return fmt.Errorf("appsec server failed: %w", err)
				}
			}

			return nil
		})
		<-t.Dying()
		w.logger.Info("Shutting down Appsec server")
		// xx let's clean up the appsec runners :)
		appsec.AppsecRulesDetails = make(map[int]appsec.RulesDetails)

		if err := w.server.Shutdown(ctx); err != nil {
			w.logger.Errorf("Error shutting down Appsec server: %s", err.Error())
		}

		return nil
	})

	return nil
}

func (w *AppsecSource) CanRun() error {
	return nil
}

func (w *AppsecSource) GetUuid() string {
	return w.config.UniqueId
}

func (w *AppsecSource) Dump() interface{} {
	return w
}

func (w *AppsecSource) IsAuth(ctx context.Context, apiKey string) bool {
	client := &http.Client{
		Timeout: 200 * time.Millisecond,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, w.lapiURL, nil)
	if err != nil {
		log.Errorf("Error creating request: %s", err)
		return false
	}

	req.Header.Add("X-Api-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error performing request: %s", err)
		return false
	}

	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// should this be in the runner ?
func (w *AppsecSource) appsecHandler(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.logger.Debugf("Received request from '%s' on %s", r.RemoteAddr, r.URL.Path)

	apiKey := r.Header.Get(appsec.APIKeyHeaderName)
	clientIP := r.Header.Get(appsec.IPHeaderName)
	remoteIP := r.RemoteAddr

	if apiKey == "" {
		w.logger.Errorf("Unauthorized request from '%s' (real IP = %s)", remoteIP, clientIP)
		rw.WriteHeader(http.StatusUnauthorized)

		return
	}

	expiration, exists := w.AuthCache.Get(apiKey)
	// if the apiKey is not in cache or has expired, just recheck the auth
	if !exists || time.Now().After(expiration) {
		if !w.IsAuth(ctx, apiKey) {
			rw.WriteHeader(http.StatusUnauthorized)
			w.logger.Errorf("Unauthorized request from '%s' (real IP = %s)", remoteIP, clientIP)

			return
		}

		// apiKey is valid, store it in cache
		w.AuthCache.Set(apiKey, time.Now().Add(*w.config.AuthCacheDuration))
	}

	// parse the request only once
	parsedRequest, err := appsec.NewParsedRequestFromRequest(r, w.logger)
	if err != nil {
		w.logger.Errorf("%s", err)
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	parsedRequest.AppsecEngine = w.config.Name

	logger := w.logger.WithFields(log.Fields{
		"request_uuid": parsedRequest.UUID,
		"client_ip":    parsedRequest.ClientIP,
	})

	AppsecReqCounter.With(prometheus.Labels{"source": parsedRequest.RemoteAddrNormalized, "appsec_engine": parsedRequest.AppsecEngine}).Inc()

	w.InChan <- parsedRequest

	/*
		response is a copy of w.AppSecRuntime.Response that is safe to use.
		As OutOfBand might still be running, the original one can be modified
	*/
	response := <-parsedRequest.ResponseChannel

	if response.InBandInterrupt {
		AppsecBlockCounter.With(prometheus.Labels{"source": parsedRequest.RemoteAddrNormalized, "appsec_engine": parsedRequest.AppsecEngine}).Inc()
	}

	statusCode, appsecResponse := w.AppsecRuntime.GenerateResponse(response, logger)
	logger.Debugf("Response: %+v", appsecResponse)

	rw.WriteHeader(statusCode)

	body, err := json.Marshal(appsecResponse)
	if err != nil {
		logger.Errorf("unable to serialize response: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
	} else {
		if _, err := rw.Write(body); err != nil {
			logger.Errorf("unable to write response: %s", err)
		}
	}
}
