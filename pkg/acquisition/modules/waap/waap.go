package wafacquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
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

// configuration structure of the acquis for the Waap
type WaapSourceConfig struct {
	ListenAddr                        string         `yaml:"listen_addr"`
	ListenPort                        int            `yaml:"listen_port"`
	CertFilePath                      string         `yaml:"cert_file"`
	KeyFilePath                       string         `yaml:"key_file"`
	Path                              string         `yaml:"path"`
	Routines                          int            `yaml:"routines"`
	WaapConfig                        string         `yaml:"waap_config"`
	WaapConfigPath                    string         `yaml:"waap_config_path"`
	AuthCacheDuration                 *time.Duration `yaml:"auth_cache_duration"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

// runtime structure of WaapSourceConfig
type WaapSource struct {
	config      WaapSourceConfig
	logger      *log.Entry
	mux         *http.ServeMux
	server      *http.Server
	addr        string
	outChan     chan types.Event
	InChan      chan waf.ParsedRequest
	WaapRuntime *waf.WaapRuntimeConfig
	WaapConfigs map[string]waf.WaapConfig
	lapiURL     string
	AuthCache   AuthCache
	WaapRunners []WaapRunner //one for each go-routine
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

func (wc *WaapSource) UnmarshalConfig(yamlConfig []byte) error {

	err := yaml.UnmarshalStrict(yamlConfig, &wc.config)
	if err != nil {
		return errors.Wrap(err, "Cannot parse waf configuration")
	}

	if wc.config.LogLevel == nil {
		level := new(log.Level)
		*level = log.InfoLevel
		wc.config.LogLevel = level
	}
	if wc.config.ListenAddr == "" {
		return fmt.Errorf("listen_addr cannot be empty")
	}

	if wc.config.ListenPort == 0 {
		return fmt.Errorf("listen_port cannot be empty")
	}

	if wc.config.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	if wc.config.Path[0] != '/' {
		wc.config.Path = "/" + wc.config.Path
	}

	if wc.config.Mode == "" {
		wc.config.Mode = configuration.TAIL_MODE
	}

	// always have at least one waf routine
	if wc.config.Routines == 0 {
		wc.config.Routines = 1
	}

	if wc.config.WaapConfig == "" && wc.config.WaapConfigPath == "" {
		return fmt.Errorf("waap_config or waap_config_path must be set")
	}

	csConfig := csconfig.GetConfig()
	wc.lapiURL = fmt.Sprintf("%sv1/decisions/stream", csConfig.API.Client.Credentials.URL)
	wc.AuthCache = NewAuthCache()

	return nil
}

func (w *WaapSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (w *WaapSource) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func (w *WaapSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	err := w.UnmarshalConfig(yamlConfig)
	if err != nil {
		return errors.Wrap(err, "unable to parse waf configuration")
	}
	w.logger = logger
	w.logger.Logger.SetLevel(*w.config.LogLevel)

	w.logger.Tracef("WAF configuration: %+v", w.config)

	if w.config.AuthCacheDuration == nil {
		w.config.AuthCacheDuration = &DefaultAuthCacheDuration
		w.logger.Infof("Cache duration for auth not set, using default: %v", *w.config.AuthCacheDuration)
	}

	w.addr = fmt.Sprintf("%s:%d", w.config.ListenAddr, w.config.ListenPort)

	w.mux = http.NewServeMux()

	w.server = &http.Server{
		Addr:    w.addr,
		Handler: w.mux,
	}

	w.InChan = make(chan waf.ParsedRequest)
	waapCfg := waf.WaapConfig{Logger: w.logger.WithField("component", "waap_config")}

	//let's load the associated waap_config:
	if w.config.WaapConfigPath != "" {
		err := waapCfg.LoadByPath(w.config.WaapConfigPath)
		if err != nil {
			return fmt.Errorf("unable to load waap_config : %s", err)
		}
	} else if w.config.WaapConfig != "" {
		err := waapCfg.Load(w.config.WaapConfig)
		if err != nil {
			return fmt.Errorf("unable to load waap_config : %s", err)
		}
	} else {
		return fmt.Errorf("no waap_config provided")
	}

	w.WaapRuntime, err = waapCfg.Build()
	if err != nil {
		return fmt.Errorf("unable to build waap_config : %s", err)
	}

	err = w.WaapRuntime.ProcessOnLoadRules()

	if err != nil {
		return fmt.Errorf("unable to process on load rules : %s", err)
	}

	w.WaapRunners = make([]WaapRunner, w.config.Routines)

	for nbRoutine := 0; nbRoutine < w.config.Routines; nbRoutine++ {

		wafUUID := uuid.New().String()
		//we copy WaapRutime for each runner
		wrt := *w.WaapRuntime
		runner := WaapRunner{
			inChan: w.InChan,
			UUID:   wafUUID,
			logger: w.logger.WithFields(log.Fields{
				"uuid": wafUUID,
			}),
			WaapRuntime: &wrt,
		}
		err := runner.Init(waapCfg.GetDataDir())
		if err != nil {
			return fmt.Errorf("unable to initialize runner : %s", err)
		}
		w.WaapRunners[nbRoutine] = runner
	}

	w.logger.Infof("Created %d waf runners", len(w.WaapRunners))

	//We don´t use the wrapper provided by coraza because we want to fully control what happens when a rule match to send the information in crowdsec
	w.mux.HandleFunc(w.config.Path, w.waapHandler)

	return nil
}

func (w *WaapSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return fmt.Errorf("WAF datasource does not support command line acquisition")
}

func (w *WaapSource) GetMode() string {
	return w.config.Mode
}

func (w *WaapSource) GetName() string {
	return "waf"
}

func (w *WaapSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("WAF datasource does not support command line acquisition")
}

func (w *WaapSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	w.outChan = out
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/waf/live")

		w.logger.Infof("%d waf runner to start", len(w.WaapRunners))
		for _, runner := range w.WaapRunners {
			runner := runner
			runner.outChan = out
			t.Go(func() error {
				defer trace.CatchPanic("crowdsec/acquis/waf/live/runner")
				return runner.Run(t)
			})
		}

		w.logger.Infof("Starting WAF server on %s:%d%s", w.config.ListenAddr, w.config.ListenPort, w.config.Path)
		t.Go(func() error {
			var err error
			if w.config.CertFilePath != "" && w.config.KeyFilePath != "" {
				err = w.server.ListenAndServeTLS(w.config.CertFilePath, w.config.KeyFilePath)
			} else {
				err = w.server.ListenAndServe()
			}

			if err != nil && err != http.ErrServerClosed {
				return errors.Wrap(err, "WAF server failed")
			}
			return nil
		})
		<-t.Dying()
		w.logger.Infof("Stopping WAF server on %s:%d%s", w.config.ListenAddr, w.config.ListenPort, w.config.Path)
		w.server.Shutdown(context.TODO())
		return nil
	})
	return nil
}

func (w *WaapSource) CanRun() error {
	return nil
}

func (w *WaapSource) GetUuid() string {
	return w.config.UniqueId
}

func (w *WaapSource) Dump() interface{} {
	return w
}

func (w *WaapSource) IsAuth(apiKey string) bool {
	client := &http.Client{
		Timeout: 200 * time.Millisecond,
	}

	req, err := http.NewRequest("HEAD", w.lapiURL, nil)
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
func (w *WaapSource) waapHandler(rw http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(waf.APIKeyHeaderName)
	if apiKey == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}
	expiration, exists := w.AuthCache.Get(apiKey)
	// if the apiKey is not in cache or has expired, just recheck the auth
	if !exists || time.Now().After(expiration) {
		if !w.IsAuth(apiKey) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		// apiKey is valid, store it in cache
		w.AuthCache.Set(apiKey, time.Now().Add(*w.config.AuthCacheDuration))
	}

	// parse the request only once
	parsedRequest, err := waf.NewParsedRequestFromRequest(r)
	if err != nil {
		log.Errorf("%s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.InChan <- parsedRequest

	response := <-parsedRequest.ResponseChannel

	waapResponse := w.WaapRuntime.GenerateResponse(response.InBandInterrupt)

	rw.WriteHeader(waapResponse.HTTPStatus)
	body, err := json.Marshal(BodyResponse{Action: waapResponse.Action})
	if err != nil {
		log.Errorf("unable to marshal response: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
	} else {
		rw.Write(body)
	}

}
