package httpacquisition

import (
	"compress/gzip"
	"context"
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

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func authorizeRequest(r *http.Request, hc *Configuration) error {
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
		for key, value := range hc.Headers {
			if r.Header.Get(key) != value {
				return errors.New("invalid headers")
			}
		}
	}

	return nil
}

func (s *Source) processRequest(w http.ResponseWriter, r *http.Request, hc *Configuration, out chan pipeline.Event) error {
	if hc.MaxBodySize != nil && r.ContentLength > *hc.MaxBodySize {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return fmt.Errorf("body size exceeds max body size: %d > %d", r.ContentLength, *hc.MaxBodySize)
	}

	srcHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}

	defer r.Body.Close()

	if s.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		s.logger.Tracef("processing request from '%s' with method '%s' and path '%s'", r.RemoteAddr, r.Method, r.URL.Path)

		bodyContent, err := httputil.DumpRequest(r, true)
		if err != nil {
			s.logger.Errorf("failed to dump request: %s", err)
		} else {
			s.logger.Tracef("request body: %s", bodyContent)
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

		line := pipeline.Line{
			Raw:     string(message),
			Src:     srcHost,
			Time:    time.Now().UTC(),
			Labels:  hc.Labels,
			Process: true,
			Module:  s.GetName(),
		}

		if s.metricsLevel == metrics.AcquisitionMetricsLevelAggregated {
			line.Src = hc.Path
		}

		evt := pipeline.MakeEvent(s.Config.UseTimeMachine, pipeline.LOG, true)
		evt.Line = line

		switch s.metricsLevel {
		case metrics.AcquisitionMetricsLevelAggregated:
			metrics.HTTPDataSourceLinesRead.With(prometheus.Labels{"path": hc.Path, "src": "", "datasource_type": ModuleName, "acquis_type": hc.Labels["type"]}).Inc()
		case metrics.AcquisitionMetricsLevelFull:
			metrics.HTTPDataSourceLinesRead.With(prometheus.Labels{"path": hc.Path, "src": srcHost, "datasource_type": ModuleName, "acquis_type": hc.Labels["type"]}).Inc()
		case metrics.AcquisitionMetricsLevelNone:
			// No metrics for this level
		}

		s.logger.Tracef("line to send: %+v", line)

		out <- evt
	}

	return nil
}

func (s *Source) RunServer(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.Config.Path, func(w http.ResponseWriter, r *http.Request) {
		if err := authorizeRequest(r, &s.Config); err != nil {
			s.logger.Errorf("failed to authorize request from '%s': %s", r.RemoteAddr, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead: // Return a 200 if the auth was successful
			s.logger.Infof("successful %s request from '%s'", r.Method, r.RemoteAddr)
			w.WriteHeader(http.StatusOK)

			if _, err := w.Write([]byte("OK")); err != nil {
				s.logger.Errorf("failed to write response: %v", err)
			}

			return
		case http.MethodPost: // POST is handled below
		default:
			s.logger.Errorf("method not allowed: %s", r.Method)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.RemoteAddr == "@" {
			// We check if request came from unix socket and if so we set to loopback
			r.RemoteAddr = "127.0.0.1:65535"
		}

		err := s.processRequest(w, r, &s.Config, out)
		if err != nil {
			s.logger.Errorf("failed to process request from '%s': %s", r.RemoteAddr, err)
			return
		}

		if s.Config.CustomHeaders != nil {
			for key, value := range s.Config.CustomHeaders {
				w.Header().Set(key, value)
			}
		}

		if s.Config.CustomStatusCode != nil {
			w.WriteHeader(*s.Config.CustomStatusCode)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if _, err := w.Write([]byte("OK")); err != nil {
			s.logger.Errorf("failed to write response: %v", err)
		}
	})

	s.Server = &http.Server{
		Addr:      s.Config.ListenAddr,
		Handler:   mux,
		Protocols: &http.Protocols{},
	}

	s.Server.Protocols.SetHTTP1(true)
	s.Server.Protocols.SetUnencryptedHTTP2(true)
	s.Server.Protocols.SetHTTP2(true)

	if s.Config.Timeout != nil {
		s.Server.ReadTimeout = *s.Config.Timeout
	}

	if s.Config.TLS != nil {
		tlsConfig, err := s.Config.NewTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create tls config: %w", err)
		}

		s.logger.Tracef("tls config: %+v", tlsConfig)
		s.Server.TLSConfig = tlsConfig
	}

	listenConfig := &net.ListenConfig{}

	t.Go(func() error {
		defer trace.ReportPanic()

		if s.Config.ListenSocket == "" {
			return nil
		}

		s.logger.Infof("creating unix socket on %s", s.Config.ListenSocket)
		_ = os.Remove(s.Config.ListenSocket)

		listener, err := listenConfig.Listen(ctx, "unix", s.Config.ListenSocket)
		if err != nil {
			return csnet.WrapSockErr(err, s.Config.ListenSocket)
		}

		if s.Config.TLS != nil {
			err := s.Server.ServeTLS(listener, s.Config.TLS.ServerCert, s.Config.TLS.ServerKey)
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("https server failed: %w", err)
			}
		} else {
			err := s.Server.Serve(listener)
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("http server failed: %w", err)
			}
		}

		return nil
	})

	t.Go(func() error {
		defer trace.ReportPanic()

		if s.Config.ListenAddr == "" {
			return nil
		}

		if s.Config.TLS != nil {
			s.logger.Infof("start https server on %s", s.Config.ListenAddr)

			err := s.Server.ListenAndServeTLS(s.Config.TLS.ServerCert, s.Config.TLS.ServerKey)
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("https server failed: %w", err)
			}
		} else {
			s.logger.Infof("start http server on %s", s.Config.ListenAddr)

			err := s.Server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("http server failed: %w", err)
			}
		}

		return nil
	})

	<-t.Dying()

	s.logger.Infof("%s datasource stopping", s.GetName())

	if err := s.Server.Close(); err != nil {
		return fmt.Errorf("while closing %s server: %w", s.GetName(), err)
	}

	return nil
}

func (s *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	s.logger.Debugf("start http server on %s", s.Config.ListenAddr)

	t.Go(func() error {
		defer trace.ReportPanic()
		return s.RunServer(ctx, out, t)
	})

	return nil
}
