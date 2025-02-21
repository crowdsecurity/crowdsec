package httpacquisition

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var dataSourceName = "http"

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_httpsource_hits_total",
		Help: "Total lines that were read from http source",
	},
	[]string{"path", "src"})

type HttpConfiguration struct {
	// IPFilter                       []string           `yaml:"ip_filter"`
	// ChunkSize                      *int64             `yaml:"chunk_size"`
	ListenAddr                        string             `yaml:"listen_addr"`
	Path                              string             `yaml:"path"`
	AuthType                          string             `yaml:"auth_type"`
	BasicAuth                         *BasicAuthConfig   `yaml:"basic_auth"`
	Headers                           *map[string]string `yaml:"headers"`
	TLS                               *TLSConfig         `yaml:"tls"`
	CustomStatusCode                  *int               `yaml:"custom_status_code"`
	CustomHeaders                     *map[string]string `yaml:"custom_headers"`
	MaxBodySize                       *int64             `yaml:"max_body_size"`
	Timeout                           *time.Duration     `yaml:"timeout"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type BasicAuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	ServerCert         string `yaml:"server_cert"`
	ServerKey          string `yaml:"server_key"`
	CaCert             string `yaml:"ca_cert"`
}

type HTTPSource struct {
	metricsLevel int
	Config       HttpConfiguration
	logger       *log.Entry
	Server       *http.Server
}

func (h *HTTPSource) GetUuid() string {
	return h.Config.UniqueId
}

func (h *HTTPSource) UnmarshalConfig(yamlConfig []byte) error {
	h.Config = HttpConfiguration{}

	err := yaml.Unmarshal(yamlConfig, &h.Config)
	if err != nil {
		return fmt.Errorf("cannot parse %s datasource configuration: %w", dataSourceName, err)
	}

	if h.Config.Mode == "" {
		h.Config.Mode = configuration.TAIL_MODE
	}

	return nil
}

func (hc *HttpConfiguration) Validate() error {
	if hc.ListenAddr == "" {
		return errors.New("listen_addr is required")
	}

	if hc.Path == "" {
		hc.Path = "/"
	}

	if hc.Path[0] != '/' {
		return errors.New("path must start with /")
	}

	switch hc.AuthType {
	case "basic_auth":
		baseErr := "basic_auth is selected, but"
		if hc.BasicAuth == nil {
			return errors.New(baseErr + " basic_auth is not provided")
		}

		if hc.BasicAuth.Username == "" {
			return errors.New(baseErr + " username is not provided")
		}

		if hc.BasicAuth.Password == "" {
			return errors.New(baseErr + " password is not provided")
		}
	case "headers":
		if hc.Headers == nil {
			return errors.New("headers is selected, but headers is not provided")
		}
	case "mtls":
		if hc.TLS == nil || hc.TLS.CaCert == "" {
			return errors.New("mtls is selected, but ca_cert is not provided")
		}
	default:
		return errors.New("invalid auth_type: must be one of basic_auth, headers, mtls")
	}

	if hc.TLS != nil {
		if hc.TLS.ServerCert == "" {
			return errors.New("server_cert is required")
		}

		if hc.TLS.ServerKey == "" {
			return errors.New("server_key is required")
		}
	}

	if hc.MaxBodySize != nil && *hc.MaxBodySize <= 0 {
		return errors.New("max_body_size must be positive")
	}

	/*
		if hc.ChunkSize != nil && *hc.ChunkSize <= 0 {
			return errors.New("chunk_size must be positive")
		}
	*/

	if hc.CustomStatusCode != nil {
		statusText := http.StatusText(*hc.CustomStatusCode)
		if statusText == "" {
			return errors.New("invalid HTTP status code")
		}
	}

	return nil
}

func (h *HTTPSource) Configure(yamlConfig []byte, logger *log.Entry, metricsLevel int) error {
	h.logger = logger
	h.metricsLevel = metricsLevel

	err := h.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	if err := h.Config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
}

func (h *HTTPSource) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("%s datasource does not support command-line acquisition", dataSourceName)
}

func (h *HTTPSource) GetMode() string {
	return h.Config.Mode
}

func (h *HTTPSource) GetName() string {
	return dataSourceName
}

func (h *HTTPSource) OneShotAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("%s datasource does not support one-shot acquisition", dataSourceName)
}

func (h *HTTPSource) CanRun() error {
	return nil
}

func (h *HTTPSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (h *HTTPSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (h *HTTPSource) Dump() interface{} {
	return h
}

func (hc *HttpConfiguration) NewTLSConfig() (*tls.Config, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: hc.TLS.InsecureSkipVerify,
	}

	if hc.TLS.ServerCert != "" && hc.TLS.ServerKey != "" {
		cert, err := tls.LoadX509KeyPair(hc.TLS.ServerCert, hc.TLS.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load server cert/key: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if hc.AuthType == "mtls" && hc.TLS.CaCert != "" {
		caCert, err := os.ReadFile(hc.TLS.CaCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read ca cert: %w", err)
		}

		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system cert pool: %w", err)
		}

		if caCertPool == nil {
			caCertPool = x509.NewCertPool()
		}

		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &tlsConfig, nil
}

func authorizeRequest(r *http.Request, hc *HttpConfiguration) error {
	if hc.AuthType == "basic_auth" {
		username, password, ok := r.BasicAuth()
		if !ok {
			return errors.New("missing basic auth")
		}

		if username != hc.BasicAuth.Username || password != hc.BasicAuth.Password {
			return errors.New("invalid basic auth")
		}
	}

	if hc.AuthType == "headers" {
		for key, value := range *hc.Headers {
			if r.Header.Get(key) != value {
				return errors.New("invalid headers")
			}
		}
	}

	return nil
}

func (h *HTTPSource) processRequest(w http.ResponseWriter, r *http.Request, hc *HttpConfiguration, out chan types.Event) error {
	if hc.MaxBodySize != nil && r.ContentLength > *hc.MaxBodySize {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return fmt.Errorf("body size exceeds max body size: %d > %d", r.ContentLength, *hc.MaxBodySize)
	}

	srcHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}

	defer r.Body.Close()

	reader := r.Body

	if r.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer reader.Close()
	}

	decoder := json.NewDecoder(reader)

	for {
		var message json.RawMessage

		if err := decoder.Decode(&message); err != nil {
			if err == io.EOF {
				break
			}

			w.WriteHeader(http.StatusBadRequest)

			return fmt.Errorf("failed to decode: %w", err)
		}

		line := types.Line{
			Raw:     string(message),
			Src:     srcHost,
			Time:    time.Now().UTC(),
			Labels:  hc.Labels,
			Process: true,
			Module:  h.GetName(),
		}

		if h.metricsLevel == configuration.METRICS_AGGREGATE {
			line.Src = hc.Path
		}

		evt := types.MakeEvent(h.Config.UseTimeMachine, types.LOG, true)
		evt.Line = line

		if h.metricsLevel == configuration.METRICS_AGGREGATE {
			linesRead.With(prometheus.Labels{"path": hc.Path, "src": ""}).Inc()
		} else if h.metricsLevel == configuration.METRICS_FULL {
			linesRead.With(prometheus.Labels{"path": hc.Path, "src": srcHost}).Inc()
		}

		h.logger.Tracef("line to send: %+v", line)
		out <- evt
	}

	return nil
}

func (h *HTTPSource) RunServer(out chan types.Event, t *tomb.Tomb) error {
	mux := http.NewServeMux()
	mux.HandleFunc(h.Config.Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			h.logger.Errorf("method not allowed: %s", r.Method)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)

			return
		}

		if err := authorizeRequest(r, &h.Config); err != nil {
			h.logger.Errorf("failed to authorize request from '%s': %s", r.RemoteAddr, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}

		err := h.processRequest(w, r, &h.Config, out)
		if err != nil {
			h.logger.Errorf("failed to process request from '%s': %s", r.RemoteAddr, err)
			return
		}

		if h.Config.CustomHeaders != nil {
			for key, value := range *h.Config.CustomHeaders {
				w.Header().Set(key, value)
			}
		}

		if h.Config.CustomStatusCode != nil {
			w.WriteHeader(*h.Config.CustomStatusCode)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		w.Write([]byte("OK"))
	})

	h.Server = &http.Server{
		Addr:      h.Config.ListenAddr,
		Handler:   mux,
		Protocols: &http.Protocols{},
	}

	h.Server.Protocols.SetHTTP1(true)
	h.Server.Protocols.SetUnencryptedHTTP2(true)
	h.Server.Protocols.SetHTTP2(true)

	if h.Config.Timeout != nil {
		h.Server.ReadTimeout = *h.Config.Timeout
	}

	if h.Config.TLS != nil {
		tlsConfig, err := h.Config.NewTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create tls config: %w", err)
		}

		h.logger.Tracef("tls config: %+v", tlsConfig)
		h.Server.TLSConfig = tlsConfig
	}

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/http/server")

		if h.Config.TLS != nil {
			h.logger.Infof("start https server on %s", h.Config.ListenAddr)

			err := h.Server.ListenAndServeTLS(h.Config.TLS.ServerCert, h.Config.TLS.ServerKey)
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("https server failed: %w", err)
			}
		} else {
			h.logger.Infof("start http server on %s", h.Config.ListenAddr)

			err := h.Server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("http server failed: %w", err)
			}
		}

		return nil
	})

	//nolint //fp
	for {
		select {
		case <-t.Dying():
			h.logger.Infof("%s datasource stopping", dataSourceName)
			if err := h.Server.Close(); err != nil {
				return fmt.Errorf("while closing %s server: %w", dataSourceName, err)
			}
			return nil
		}
	}
}

func (h *HTTPSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	h.logger.Debugf("start http server on %s", h.Config.ListenAddr)

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/http/live")
		return h.RunServer(out, t)
	})

	return nil
}
