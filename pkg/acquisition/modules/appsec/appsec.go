package appsecacquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

const (
	InBand    = "inband"
	OutOfBand = "outofband"
)

var (
	DefaultAuthCacheDuration = (1 * time.Minute)
)

// configuration structure of the acquis for the application security engine
type AppsecSourceConfig struct {
	ListenAddr                        string         `yaml:"listen_addr"`
	CertFilePath                      string         `yaml:"cert_file"`
	KeyFilePath                       string         `yaml:"key_file"`
	Path                              string         `yaml:"path"`
	Routines                          int            `yaml:"routines"`
	AppsecConfig                      string         `yaml:"appsec_config"`
	AppsecConfigPath                  string         `yaml:"appsec_config_path"`
	AuthCacheDuration                 *time.Duration `yaml:"auth_cache_duration"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

// runtime structure of AppsecSourceConfig
type AppsecSource struct {
	config        AppsecSourceConfig
	logger        *log.Entry
	mux           *http.ServeMux
	server        *http.Server
	outChan       chan types.Event
	InChan        chan appsec.ParsedRequest
	AppsecRuntime *appsec.AppsecRuntimeConfig
	AppsecConfigs map[string]appsec.AppsecConfig
	lapiURL       string
	AuthCache     AuthCache
	AppsecRunners []AppsecRunner //one for each go-routine
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
		return errors.Wrap(err, "Cannot parse appsec configuration")
	}

	if w.config.ListenAddr == "" {
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

	if w.config.AppsecConfig == "" && w.config.AppsecConfigPath == "" {
		return fmt.Errorf("appsec_config or appsec_config_path must be set")
	}

	if w.config.Name == "" {
		w.config.Name = fmt.Sprintf("%s%s", w.config.ListenAddr, w.config.Path)
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

func (w *AppsecSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	err := w.UnmarshalConfig(yamlConfig)
	if err != nil {
		return errors.Wrap(err, "unable to parse appsec configuration")
	}
	w.logger = logger

	w.logger.Tracef("Appsec configuration: %+v", w.config)

	if w.config.AuthCacheDuration == nil {
		w.config.AuthCacheDuration = &DefaultAuthCacheDuration
		w.logger.Infof("Cache duration for auth not set, using default: %v", *w.config.AuthCacheDuration)
	}

	w.mux = http.NewServeMux()

	w.server = &http.Server{
		Addr:    w.config.ListenAddr,
		Handler: w.mux,
	}

	w.InChan = make(chan appsec.ParsedRequest)
	appsecCfg := appsec.AppsecConfig{Logger: w.logger.WithField("component", "appsec_config")}

	//let's load the associated appsec_config:
	if w.config.AppsecConfigPath != "" {
		err := appsecCfg.LoadByPath(w.config.AppsecConfigPath)
		if err != nil {
			return fmt.Errorf("unable to load appsec_config : %s", err)
		}
	} else if w.config.AppsecConfig != "" {
		err := appsecCfg.Load(w.config.AppsecConfig)
		if err != nil {
			return fmt.Errorf("unable to load appsec_config : %s", err)
		}
	} else {
		return fmt.Errorf("no appsec_config provided")
	}

	w.AppsecRuntime, err = appsecCfg.Build()
	if err != nil {
		return fmt.Errorf("unable to build appsec_config : %s", err)
	}

	err = w.AppsecRuntime.ProcessOnLoadRules()

	if err != nil {
		return fmt.Errorf("unable to process on load rules : %s", err)
	}

	w.AppsecRunners = make([]AppsecRunner, w.config.Routines)

	for nbRoutine := 0; nbRoutine < w.config.Routines; nbRoutine++ {
		appsecRunnerUUID := uuid.New().String()
		//we copy AppsecRutime for each runner
		wrt := *w.AppsecRuntime
		wrt.Logger = w.logger.Dup().WithField("runner_uuid", appsecRunnerUUID)
		runner := AppsecRunner{
			inChan: w.InChan,
			UUID:   appsecRunnerUUID,
			logger: w.logger.WithFields(log.Fields{
				"runner_uuid": appsecRunnerUUID,
			}),
			AppsecRuntime: &wrt,
			Labels:        w.config.Labels,
		}
		err := runner.Init(appsecCfg.GetDataDir())
		if err != nil {
			return fmt.Errorf("unable to initialize runner : %s", err)
		}
		w.AppsecRunners[nbRoutine] = runner
	}

	w.logger.Infof("Created %d appsec runners", len(w.AppsecRunners))

	//We don´t use the wrapper provided by coraza because we want to fully control what happens when a rule match to send the information in crowdsec
	w.mux.HandleFunc(w.config.Path, w.appsecHandler)
	return nil
}

func (w *AppsecSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return fmt.Errorf("AppSec datasource does not support command line acquisition")
}

func (w *AppsecSource) GetMode() string {
	return w.config.Mode
}

func (w *AppsecSource) GetName() string {
	return "appsec"
}

func (w *AppsecSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("AppSec datasource does not support command line acquisition")
}

func (w *AppsecSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	w.outChan = out
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/appsec/live")

		w.logger.Infof("%d appsec runner to start", len(w.AppsecRunners))
		for _, runner := range w.AppsecRunners {
			runner := runner
			runner.outChan = out
			t.Go(func() error {
				defer trace.CatchPanic("crowdsec/acquis/appsec/live/runner")
				return runner.Run(t)
			})
		}

		w.logger.Infof("Starting Appsec server on %s%s", w.config.ListenAddr, w.config.Path)
		t.Go(func() error {
			var err error
			if w.config.CertFilePath != "" && w.config.KeyFilePath != "" {
				err = w.server.ListenAndServeTLS(w.config.CertFilePath, w.config.KeyFilePath)
			} else {
				err = w.server.ListenAndServe()
			}

			if err != nil && err != http.ErrServerClosed {
				return errors.Wrap(err, "Appsec server failed")
			}
			return nil
		})
		<-t.Dying()
		w.logger.Infof("Stopping Appsec server on %s%s", w.config.ListenAddr, w.config.Path)
		w.server.Shutdown(context.TODO())
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

func (w *AppsecSource) IsAuth(apiKey string) bool {
	client := &http.Client{
		Timeout: 200 * time.Millisecond,
	}

	req, err := http.NewRequest(http.MethodHead, w.lapiURL, nil)
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
		if !w.IsAuth(apiKey) {
			rw.WriteHeader(http.StatusUnauthorized)
			w.logger.Errorf("Unauthorized request from '%s' (real IP = %s)", remoteIP, clientIP)
			return
		}

		// apiKey is valid, store it in cache
		w.AuthCache.Set(apiKey, time.Now().Add(*w.config.AuthCacheDuration))
	}

	// parse the request only once
	parsedRequest, err := appsec.NewParsedRequestFromRequest(r)
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

	response := <-parsedRequest.ResponseChannel
	if response.InBandInterrupt {
		AppsecBlockCounter.With(prometheus.Labels{"source": parsedRequest.RemoteAddrNormalized, "appsec_engine": parsedRequest.AppsecEngine}).Inc()
	}

	appsecResponse := w.AppsecRuntime.GenerateResponse(response, logger)
	logger.Debugf("Response: %+v", appsecResponse)
	rw.WriteHeader(appsecResponse.HTTPStatus)
	body, err := json.Marshal(BodyResponse{Action: appsecResponse.Action})
	if err != nil {
		logger.Errorf("unable to marshal response: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
	} else {
		rw.Write(body)
	}

}
