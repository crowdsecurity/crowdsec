package appsecacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/allowlists"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	InBand    = "inband"
	OutOfBand = "outofband"
)

var (
	errMissingAPIKey = errors.New("missing API key")
	errInvalidAPIKey = errors.New("invalid API key")
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
	config                AppsecSourceConfig
	logger                *log.Entry
	mux                   *http.ServeMux
	server                *http.Server
	InChan                chan appsec.ParsedRequest
	AppsecRuntime         *appsec.AppsecRuntimeConfig
	AppsecConfigs         map[string]appsec.AppsecConfig
	lapiURL               string
	AuthCache             AuthCache
	AppsecRunners         []AppsecRunner // one for each go-routine
	appsecAllowlistClient *allowlists.AppsecAllowlist
	lapiCACertPool        *x509.CertPool
	authMutex             sync.Mutex
	httpClient            *http.Client
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

func (ac *AuthCache) Delete(apiKey string) {
	ac.mu.Lock()
	delete(ac.APIKeys, apiKey)
	ac.mu.Unlock()
}

// @tko + @sbl : we might want to get rid of that or improve it
type BodyResponse struct {
	Action string `json:"action"`
}

func (w *AppsecSource) UnmarshalConfig(yamlConfig []byte) error {
	err := yaml.UnmarshalWithOptions(yamlConfig, &w.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse appsec configuration: %s", yaml.FormatError(err, false, false))
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

func (*AppsecSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.AppsecReqCounter, metrics.AppsecBlockCounter, metrics.AppsecRuleHits,
		metrics.AppsecOutbandParsingHistogram, metrics.AppsecInbandParsingHistogram, metrics.AppsecGlobalParsingHistogram}
}

func (*AppsecSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.AppsecReqCounter, metrics.AppsecBlockCounter, metrics.AppsecRuleHits,
		metrics.AppsecOutbandParsingHistogram, metrics.AppsecInbandParsingHistogram, metrics.AppsecGlobalParsingHistogram}
}

func loadCertPool(caCertPath string, logger log.FieldLogger) (*x509.CertPool, error) {
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		logger.Warnf("Error loading system CA certificates: %s", err)
	}

	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}

	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("while opening cert file: %w", err)
		}

		caCertPool.AppendCertsFromPEM(caCert)
	}

	return caCertPool, nil
}

func (w *AppsecSource) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	err := w.UnmarshalConfig(yamlConfig)
	if err != nil {
		return fmt.Errorf("unable to parse appsec configuration: %w", err)
	}

	w.logger = logger
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

	w.appsecAllowlistClient = allowlists.NewAppsecAllowlist(w.logger)

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

		if err = runner.Init(appsecCfg.GetDataDir()); err != nil {
			return fmt.Errorf("unable to initialize runner: %w", err)
		}

		w.AppsecRunners[nbRoutine] = runner
	}

	w.logger.Infof("Created %d appsec runners", len(w.AppsecRunners))

	// We don´t use the wrapper provided by coraza because we want to fully control what happens when a rule match to send the information in crowdsec
	w.mux.HandleFunc(w.config.Path, w.appsecHandler)

	csConfig := csconfig.GetConfig()

	caCertPath := ""

	if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil {
		caCertPath = csConfig.API.Client.Credentials.CACertPath
	}

	w.lapiCACertPool, err = loadCertPool(caCertPath, w.logger)
	if err != nil {
		return fmt.Errorf("unable to load LAPI CA cert pool: %w", err)
	}

	w.httpClient = &http.Client{
		Timeout: 200 * time.Millisecond,
	}
	if w.lapiCACertPool != nil {
		w.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: w.lapiCACertPool,
			},
		}
	}

	return nil
}

func (w *AppsecSource) GetMode() string {
	return w.config.Mode
}

func (*AppsecSource) GetName() string {
	return "appsec"
}

func (w *AppsecSource) listenAndServe(ctx context.Context, t *tomb.Tomb) error {
	defer trace.CatchPanic("crowdsec/acquis/appsec/listenAndServe")

	w.logger.Infof("%d appsec runner to start", len(w.AppsecRunners))

	serverError := make(chan error, 2)

	startServer := func(listener net.Listener, canTLS bool) {
		var err error

		if canTLS && (w.config.CertFilePath != "" || w.config.KeyFilePath != "") {
			if w.config.KeyFilePath == "" {
				serverError <- errors.New("missing TLS key file")
				return
			}

			if w.config.CertFilePath == "" {
				serverError <- errors.New("missing TLS cert file")
				return
			}

			err = w.server.ServeTLS(listener, w.config.CertFilePath, w.config.KeyFilePath)
		} else {
			err = w.server.Serve(listener)
		}

		switch {
		case errors.Is(err, http.ErrServerClosed):
			break
		case err != nil:
			serverError <- err
		}
	}

	listenConfig := &net.ListenConfig{}

	// Starting Unix socket listener
	go func(socket string) {
		if socket == "" {
			return
		}

		if err := os.Remove(w.config.ListenSocket); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				w.logger.Errorf("can't remove socket %s: %s", socket, err)
			}
		}

		w.logger.Infof("creating unix socket %s", socket)

		listener, err := listenConfig.Listen(ctx, "unix", socket)
		if err != nil {
			serverError <- csnet.WrapSockErr(err, socket)
			return
		}

		w.logger.Infof("Appsec listening on Unix socket %s", socket)
		startServer(listener, false)
	}(w.config.ListenSocket)

	// Starting TCP listener
	go func(url string) {
		if url == "" {
			return
		}

		listener, err := listenConfig.Listen(ctx, "tcp", url)
		if err != nil {
			serverError <- fmt.Errorf("listening on %s: %w", url, err)
			return
		}

		w.logger.Infof("Appsec listening on %s", url)
		startServer(listener, true)
	}(w.config.ListenAddr)

	select {
	case err := <-serverError:
		return err
	case <-t.Dying():
		w.logger.Info("Shutting down Appsec server")
		// xx let's clean up the appsec runners :)
		appsec.AppsecRulesDetails = make(map[int]appsec.RulesDetails)

		if err := w.server.Shutdown(ctx); err != nil {
			w.logger.Errorf("Error shutting down Appsec server: %s", err.Error())
		}

		if w.config.ListenSocket != "" {
			if err := os.Remove(w.config.ListenSocket); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					w.logger.Errorf("can't remove socket %s: %s", w.config.ListenSocket, err)
				}
			}
		}
	}

	return nil
}

func (w *AppsecSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	apiClient, err := apiclient.GetLAPIClient()
	if err != nil {
		return fmt.Errorf("unable to get authenticated LAPI client: %w", err)
	}

	err = w.appsecAllowlistClient.Start(ctx, apiClient)
	if err != nil {
		w.logger.Errorf("failed to fetch allowlists for appsec, disabling them: %s", err)
	} else {
		w.appsecAllowlistClient.StartRefresh(ctx, t)
	}

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/appsec/live")

		for _, runner := range w.AppsecRunners {
			runner.outChan = out

			t.Go(func() error {
				defer trace.CatchPanic("crowdsec/acquis/appsec/live/runner")
				return runner.Run(t)
			})
		}

		return w.listenAndServe(ctx, t)
	})

	return nil
}

func (*AppsecSource) CanRun() error {
	return nil
}

func (w *AppsecSource) GetUuid() string {
	return w.config.UniqueId
}

func (w *AppsecSource) Dump() any {
	return w
}

func (w *AppsecSource) isValidKey(ctx context.Context, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, w.lapiURL, http.NoBody)
	if err != nil {
		w.logger.Errorf("Error creating request: %s", err)
		return false, err
	}

	req.Header.Add("X-Api-Key", apiKey)
	req.Header.Add("User-Agent", useragent.AppsecUserAgent())

	resp, err := w.httpClient.Do(req)
	if err != nil {
		w.logger.Errorf("Error performing request: %s", err)
		return false, err
	}

	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

func (w *AppsecSource) checkAuth(ctx context.Context, apiKey string) error {
	if apiKey == "" {
		return errMissingAPIKey
	}

	w.authMutex.Lock()
	defer w.authMutex.Unlock()

	expiration, exists := w.AuthCache.Get(apiKey)
	now := time.Now()

	if !exists { // No key in cache, require a valid check
		isAuth, err := w.isValidKey(ctx, apiKey)
		if err != nil || !isAuth {
			if err != nil {
				w.logger.Errorf("Error checking auth for API key: %s", err)
			}

			return errInvalidAPIKey
		}
		// Cache the valid API key
		w.AuthCache.Set(apiKey, now.Add(*w.config.AuthCacheDuration))

		return nil
	}

	if now.After(expiration) { // Key is expired, recheck the value OR keep it if we cannot contact LAPI
		isAuth, err := w.isValidKey(ctx, apiKey)
		if isAuth {
			w.AuthCache.Set(apiKey, now.Add(*w.config.AuthCacheDuration))
		} else if err != nil { // General error when querying LAPI, consider the key still valid
			w.logger.Errorf("Error checking auth for API key: %s, extending cache duration", err)
			w.AuthCache.Set(apiKey, now.Add(*w.config.AuthCacheDuration))
		} else { // Key is not valid, remove it from cache
			w.AuthCache.Delete(apiKey)
			return errInvalidAPIKey
		}
	}

	return nil
}

// should this be in the runner ?
func (w *AppsecSource) appsecHandler(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.logger.Debugf("Received request from '%s' on %s", r.RemoteAddr, r.URL.Path)

	apiKey := r.Header.Get(appsec.APIKeyHeaderName)
	clientIP := r.Header.Get(appsec.IPHeaderName)
	remoteIP := r.RemoteAddr

	if err := w.checkAuth(ctx, apiKey); err != nil {
		w.logger.Errorf("Unauthorized request from '%s' (real IP = %s): %s", remoteIP, clientIP, err)
		rw.WriteHeader(http.StatusUnauthorized)
		return
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

	metrics.AppsecReqCounter.With(prometheus.Labels{"source": parsedRequest.RemoteAddrNormalized, "appsec_engine": parsedRequest.AppsecEngine}).Inc()

	w.InChan <- parsedRequest

	/*
		response is a copy of w.AppSecRuntime.Response that is safe to use.
		As OutOfBand might still be running, the original one can be modified
	*/
	response := <-parsedRequest.ResponseChannel

	if response.InBandInterrupt {
		metrics.AppsecBlockCounter.With(prometheus.Labels{"source": parsedRequest.RemoteAddrNormalized, "appsec_engine": parsedRequest.AppsecEngine}).Inc()
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
