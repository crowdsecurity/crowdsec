package loki

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
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki/internal/lokiclient"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

const lokiLimit int = 100

type AuthConfiguration struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Configuration struct {
	URL                               string            `yaml:"url"`    // Loki url
	Prefix                            string            `yaml:"prefix"` // Loki prefix
	Query                             string            `yaml:"query"`  // LogQL query
	Limit                             int               `yaml:"limit"`  // Limit of logs to read
	DelayFor                          time.Duration     `yaml:"delay_for"`
	Since                             time.Duration     `yaml:"since"`
	Headers                           map[string]string `yaml:"headers"`        // HTTP headers for talking to Loki
	WaitForReady                      time.Duration     `yaml:"wait_for_ready"` // Retry interval, default is 10 seconds
	Auth                              AuthConfiguration `yaml:"auth"`
	MaxFailureDuration                time.Duration     `yaml:"max_failure_duration"` // Max duration of failure before stopping the source
	NoReadyCheck                      bool              `yaml:"no_ready_check"`       // Bypass /ready check before starting
	configuration.DataSourceCommonCfg                   `yaml:",inline"`
}

func (l *Source) UnmarshalConfig(yamlConfig []byte) error {
	err := yaml.UnmarshalWithOptions(yamlConfig, &l.Config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse loki acquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if l.Config.Query == "" {
		return errors.New("loki query is mandatory")
	}

	if l.Config.WaitForReady == 0 {
		l.Config.WaitForReady = 10 * time.Second
	}

	if l.Config.DelayFor < 0*time.Second || l.Config.DelayFor > 5*time.Second {
		return errors.New("delay_for should be a value between 1s and 5s")
	}

	if l.Config.Mode == "" {
		l.Config.Mode = configuration.TAIL_MODE
	}

	if l.Config.Prefix == "" {
		l.Config.Prefix = "/"
	}

	if !strings.HasSuffix(l.Config.Prefix, "/") {
		l.Config.Prefix += "/"
	}

	if l.Config.Limit == 0 {
		l.Config.Limit = lokiLimit
	}

	if l.Config.Mode == configuration.TAIL_MODE {
		l.logger.Infof("Resetting since")
		l.Config.Since = 0
	}

	if l.Config.MaxFailureDuration == 0 {
		l.Config.MaxFailureDuration = 30 * time.Second
	}

	return nil
}

func (l *Source) Configure(_ context.Context, config []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	l.Config = Configuration{}
	l.logger = logger
	l.metricsLevel = metricsLevel

	if err := l.UnmarshalConfig(config); err != nil {
		return err
	}

	l.logger.Infof("Since value: %s", l.Config.Since.String())

	clientConfig := lokiclient.Config{
		LokiURL:         l.Config.URL,
		Headers:         l.Config.Headers,
		Limit:           l.Config.Limit,
		Query:           l.Config.Query,
		Since:           l.Config.Since,
		Username:        l.Config.Auth.Username,
		Password:        l.Config.Auth.Password,
		FailMaxDuration: l.Config.MaxFailureDuration,
	}

	l.Client = lokiclient.NewLokiClient(clientConfig)
	l.Client.Logger = logger.WithFields(log.Fields{"component": "lokiclient", "source": l.Config.URL})

	return nil
}

func (l *Source) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	l.logger = logger
	l.Config = Configuration{}
	l.Config.Mode = configuration.CAT_MODE
	l.Config.Labels = labels
	l.Config.UniqueId = uuid

	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("while parsing dsn '%s': %w", dsn, err)
	}

	if u.Scheme != "loki" {
		return fmt.Errorf("invalid DSN %s for loki source, must start with loki://", dsn)
	}

	if u.Host == "" {
		return errors.New("empty loki host")
	}

	scheme := "http"

	params := u.Query()
	if q := params.Get("ssl"); q != "" {
		scheme = "https"
	}

	if q := params.Get("query"); q != "" {
		l.Config.Query = q
	}

	if w := params.Get("wait_for_ready"); w != "" {
		l.Config.WaitForReady, err = time.ParseDuration(w)
		if err != nil {
			return err
		}
	} else {
		l.Config.WaitForReady = 10 * time.Second
	}

	if d := params.Get("delay_for"); d != "" {
		l.Config.DelayFor, err = time.ParseDuration(d)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}

		if l.Config.DelayFor < 0*time.Second || l.Config.DelayFor > 5*time.Second {
			return errors.New("delay_for should be a value between 1s and 5s")
		}
	} else {
		l.Config.DelayFor = 0 * time.Second
	}

	if s := params.Get("since"); s != "" {
		l.Config.Since, err = time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid since in dsn: %w", err)
		}
	}

	if maxFailureDuration := params.Get("max_failure_duration"); maxFailureDuration != "" {
		duration, err := time.ParseDuration(maxFailureDuration)
		if err != nil {
			return fmt.Errorf("invalid max_failure_duration in dsn: %w", err)
		}

		l.Config.MaxFailureDuration = duration
	} else {
		l.Config.MaxFailureDuration = 5 * time.Second // for OneShot mode it doesn't make sense to have longer duration
	}

	if limit := params.Get("limit"); limit != "" {
		limit, err := strconv.Atoi(limit)
		if err != nil {
			return fmt.Errorf("invalid limit in dsn: %w", err)
		}

		l.Config.Limit = limit
	} else {
		l.Config.Limit = 5000 // max limit allowed by loki
	}

	if logLevel := params.Get("log_level"); logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			return fmt.Errorf("invalid log_level in dsn: %w", err)
		}

		l.Config.LogLevel = level
		l.logger.Logger.SetLevel(level)
	}

	if noReadyCheck := params.Get("no_ready_check"); noReadyCheck != "" {
		noReadyCheck, err := strconv.ParseBool(noReadyCheck)
		if err != nil {
			return fmt.Errorf("invalid no_ready_check in dsn: %w", err)
		}

		l.Config.NoReadyCheck = noReadyCheck
	}

	l.Config.URL = fmt.Sprintf("%s://%s", scheme, u.Host)
	if u.User != nil {
		l.Config.Auth.Username = u.User.Username()
		l.Config.Auth.Password, _ = u.User.Password()
	}

	clientConfig := lokiclient.Config{
		LokiURL:  l.Config.URL,
		Headers:  l.Config.Headers,
		Limit:    l.Config.Limit,
		Query:    l.Config.Query,
		Since:    l.Config.Since,
		Username: l.Config.Auth.Username,
		Password: l.Config.Auth.Password,
		DelayFor: int(l.Config.DelayFor / time.Second),
	}

	l.Client = lokiclient.NewLokiClient(clientConfig)
	l.Client.Logger = logger.WithFields(log.Fields{"component": "lokiclient", "source": l.Config.URL})

	return nil
}
