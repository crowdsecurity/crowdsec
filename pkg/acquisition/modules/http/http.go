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
	"net/http/httputil"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const dataSourceName = "http"

type HttpConfiguration struct {
	// IPFilter                       []string           `yaml:"ip_filter"`
	// ChunkSize                      *int64             `yaml:"chunk_size"`
	ListenAddr                        string             `yaml:"listen_addr"`
	ListenSocket                      string             `yaml:"listen_socket"`
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
	metricsLevel metrics.AcquisitionMetricsLevel
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
	if hc.ListenAddr == "" && hc.ListenSocket == "" {
		return errors.New("listen_addr or listen_socket is required")
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

func (h *HTTPSource) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
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

func (h *HTTPSource) GetMode() string {
	return h.Config.Mode
}

func (*HTTPSource) GetName() string {
	return dataSourceName
}

func (*HTTPSource) CanRun() error {
	return nil
}

func (*HTTPSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.HTTPDataSourceLinesRead}
}

func (*HTTPSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.HTTPDataSourceLinesRead}
}

func (h *HTTPSource) Dump() any {
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

	if h.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		h.logger.Tracef("processing request from '%s' with method '%s' and path '%s'", r.RemoteAddr, r.Method, r.URL.Path)

		bodyContent, err := httputil.DumpRequest(r, true)
		if err != nil {
			h.logger.Errorf("failed to dump request: %s", err)
		} else {
			h.logger.Tracef("request body: %s", bodyContent)
		}
	}

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

		if h.metricsLevel == metrics.AcquisitionMetricsLevelAggregated {
			line.Src = hc.Path
		}

		evt := types.MakeEvent(h.Config.UseTimeMachine, types.LOG, true)
		evt.Line = line

		switch h.metricsLevel {
		case metrics.AcquisitionMetricsLevelAggregated:
			metrics.HTTPDataSourceLinesRead.With(prometheus.Labels{"path": hc.Path, "src": "", "datasource_type": "http", "acquis_type": hc.Labels["type"]}).Inc()
		case metrics.AcquisitionMetricsLevelFull:
			metrics.HTTPDataSourceLinesRead.With(prometheus.Labels{"path": hc.Path, "src": srcHost, "datasource_type": "http", "acquis_type": hc.Labels["type"]}).Inc()
		case metrics.AcquisitionMetricsLevelNone:
			// No metrics for this level
		}

		h.logger.Tracef("line to send: %+v", line)

		out <- evt
	}

	return nil
}

func (h *HTTPSource) RunServer(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	mux := http.NewServeMux()
	mux.HandleFunc(h.Config.Path, func(w http.ResponseWriter, r *http.Request) {
		if err := authorizeRequest(r, &h.Config); err != nil {
			h.logger.Errorf("failed to authorize request from '%s': %s", r.RemoteAddr, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead: // Return a 200 if the auth was successful
			h.logger.Infof("successful %s request from '%s'", r.Method, r.RemoteAddr)
			w.WriteHeader(http.StatusOK)

			if _, err := w.Write([]byte("OK")); err != nil {
				h.logger.Errorf("failed to write response: %v", err)
			}

			return
		case http.MethodPost: // POST is handled below
		default:
			h.logger.Errorf("method not allowed: %s", r.Method)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.RemoteAddr == "@" {
			// We check if request came from unix socket and if so we set to loopback
			r.RemoteAddr = "127.0.0.1:65535"
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

		if _, err := w.Write([]byte("OK")); err != nil {
			h.logger.Errorf("failed to write response: %v", err)
		}
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

	listenConfig := &net.ListenConfig{}

	t.Go(func() error {
		if h.Config.ListenSocket == "" {
			return nil
		}

		defer trace.CatchPanic("crowdsec/acquis/http/server/unix")

		h.logger.Infof("creating unix socket on %s", h.Config.ListenSocket)
		_ = os.Remove(h.Config.ListenSocket)

		listener, err := listenConfig.Listen(ctx, "unix", h.Config.ListenSocket)
		if err != nil {
			return csnet.WrapSockErr(err, h.Config.ListenSocket)
		}

		if h.Config.TLS != nil {
			err := h.Server.ServeTLS(listener, h.Config.TLS.ServerCert, h.Config.TLS.ServerKey)
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("https server failed: %w", err)
			}
		} else {
			err := h.Server.Serve(listener)
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("http server failed: %w", err)
			}
		}

		return nil
	})

	t.Go(func() error {
		if h.Config.ListenAddr == "" {
			return nil
		}

		defer trace.CatchPanic("crowdsec/acquis/http/server/tcp")

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

	<-t.Dying()

	h.logger.Infof("%s datasource stopping", dataSourceName)

	if err := h.Server.Close(); err != nil {
		return fmt.Errorf("while closing %s server: %w", dataSourceName, err)
	}

	return nil
}

func (h *HTTPSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	h.logger.Debugf("start http server on %s", h.Config.ListenAddr)

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/http/live")
		return h.RunServer(ctx, out, t)
	})

	return nil
}
