package appsecacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/allowlists"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

var (
	errMissingAPIKey = errors.New("missing API key")
	errInvalidAPIKey = errors.New("invalid API key")
)

var DefaultAuthCacheDuration = (1 * time.Minute)

// configuration structure of the acquis for the application security engine
type Configuration struct {
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

func (w *Source) UnmarshalConfig(yamlConfig []byte) error {
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

func (w *Source) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	if w.hub == nil {
		return errors.New("appsec datasource requires a hub. this is a bug, please report")
	}

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
		if err = appsecCfg.Load(w.config.AppsecConfig, w.hub); err != nil {
			return fmt.Errorf("unable to load appsec_config: %w", err)
		}
	} else if len(w.config.AppsecConfigs) > 0 {
		for _, appsecConfig := range w.config.AppsecConfigs {
			if err = appsecCfg.Load(appsecConfig, w.hub); err != nil {
				return fmt.Errorf("unable to load appsec_config: %w", err)
			}
		}
	} else {
		return errors.New("no appsec_config provided")
	}

	// Now we can set up the logger
	appsecCfg.SetUpLogger()

	w.AppsecRuntime, err = appsecCfg.Build(w.hub)
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

		if err = runner.Init(w.hub.GetDataDir()); err != nil {
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

func (w *Source) isValidKey(ctx context.Context, apiKey string) (bool, error) {
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

func (w *Source) checkAuth(ctx context.Context, apiKey string) error {
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
func (w *Source) appsecHandler(rw http.ResponseWriter, r *http.Request) {
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
