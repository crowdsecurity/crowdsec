package victorialogs

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs/internal/vlclient"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

const (
	defaultLimit int = 100
)

type AuthConfiguration struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Configuration struct {
	URL                               string              `yaml:"url"`    // VictoriaLogs url
	Prefix                            string              `yaml:"prefix"` // VictoriaLogs prefix
	Query                             string              `yaml:"query"`  // LogsQL query
	Limit                             int                 `yaml:"limit"`  // Limit of logs to read
	Since                             time.Duration       `yaml:"since"`
	Headers                           map[string]string   `yaml:"headers"`        // HTTP headers for talking to VictoriaLogs
	WaitForReady                      time.Duration       `yaml:"wait_for_ready"` // Retry interval, default is 10 seconds
	Auth                              AuthConfiguration `yaml:"auth"`
	MaxFailureDuration                time.Duration       `yaml:"max_failure_duration"` // Max duration of failure before stopping the source
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	err := yaml.UnmarshalWithOptions(yamlConfig, &s.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse VictoriaLogs acquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.Config.URL == "" {
		return errors.New("VictoriaLogs url is mandatory")
	}

	if s.Config.Query == "" {
		return errors.New("VictoriaLogs query is mandatory")
	}

	if s.Config.WaitForReady == 0 {
		s.Config.WaitForReady = 10 * time.Second
	}

	if s.Config.Mode == "" {
		s.Config.Mode = configuration.TAIL_MODE
	}

	if s.Config.Prefix == "" {
		s.Config.Prefix = "/"
	}

	if !strings.HasSuffix(s.Config.Prefix, "/") {
		s.Config.Prefix += "/"
	}

	if s.Config.Limit == 0 {
		s.Config.Limit = defaultLimit
	}

	if s.Config.Mode == configuration.TAIL_MODE {
		s.logger.Infof("Resetting since")
		s.Config.Since = 0
	}

	if s.Config.MaxFailureDuration == 0 {
		s.Config.MaxFailureDuration = 30 * time.Second
	}

	return nil
}

func (s *Source) Configure(_ context.Context, config []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.Config = Configuration{}
	s.logger = logger
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(config)
	if err != nil {
		return err
	}

	s.logger.Infof("Since value: %s", s.Config.Since.String())

	clientConfig := vlclient.Config{
		URL:             s.Config.URL,
		Headers:         s.Config.Headers,
		Limit:           s.Config.Limit,
		Query:           s.Config.Query,
		Since:           s.Config.Since,
		Username:        s.Config.Auth.Username,
		Password:        s.Config.Auth.Password,
		FailMaxDuration: s.Config.MaxFailureDuration,
	}

	s.Client = vlclient.NewVLClient(clientConfig)
	s.Client.Logger = logger.WithFields(log.Fields{"component": "victorialogs-client", "source": s.Config.URL})

	return nil
}

func (s *Source) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	s.logger = logger
	s.Config = Configuration{}
	s.Config.Mode = configuration.CAT_MODE
	s.Config.Labels = labels
	s.Config.UniqueId = uuid

	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("while parsing dsn '%s': %w", dsn, err)
	}

	if u.Scheme != "victorialogs" {
		return fmt.Errorf("invalid DSN %s for VictoriaLogs source, must start with victorialogs://", dsn)
	}

	if u.Host == "" {
		return errors.New("empty host")
	}

	scheme := "http"

	params := u.Query()

	if q := params.Get("ssl"); q != "" {
		scheme = "https"
	}

	if q := params.Get("query"); q != "" {
		s.Config.Query = q
	}

	if w := params.Get("wait_for_ready"); w != "" {
		s.Config.WaitForReady, err = time.ParseDuration(w)
		if err != nil {
			return err
		}
	} else {
		s.Config.WaitForReady = 10 * time.Second
	}

	if since := params.Get("since"); since != "" {
		s.Config.Since, err = time.ParseDuration(since)
		if err != nil {
			return fmt.Errorf("invalid since in dsn: %w", err)
		}
	}

	if maxFailureDuration := params.Get("max_failure_duration"); maxFailureDuration != "" {
		duration, err := time.ParseDuration(maxFailureDuration)
		if err != nil {
			return fmt.Errorf("invalid max_failure_duration in dsn: %w", err)
		}

		s.Config.MaxFailureDuration = duration
	} else {
		s.Config.MaxFailureDuration = 5 * time.Second // for OneShot mode it doesn't make sense to have longer duration
	}

	if limit := params.Get("limit"); limit != "" {
		limit, err := strconv.Atoi(limit)
		if err != nil {
			return fmt.Errorf("invalid limit in dsn: %w", err)
		}

		s.Config.Limit = limit
	}

	if logLevel := params.Get("log_level"); logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			return fmt.Errorf("invalid log_level in dsn: %w", err)
		}

		s.Config.LogLevel = level
		s.logger.Logger.SetLevel(level)
	}

	s.Config.URL = fmt.Sprintf("%s://%s", scheme, u.Host)
	if u.User != nil {
		s.Config.Auth.Username = u.User.Username()
		s.Config.Auth.Password, _ = u.User.Password()
	}

	clientConfig := vlclient.Config{
		URL:      s.Config.URL,
		Headers:  s.Config.Headers,
		Limit:    s.Config.Limit,
		Query:    s.Config.Query,
		Since:    s.Config.Since,
		Username: s.Config.Auth.Username,
		Password: s.Config.Auth.Password,
	}

	s.Client = vlclient.NewVLClient(clientConfig)
	s.Client.Logger = logger.WithFields(log.Fields{"component": "victorialogs-client", "source": s.Config.URL})

	return nil
}
