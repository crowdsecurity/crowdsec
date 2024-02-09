package loki

/*
https://grafana.com/docs/loki/latest/api/#get-lokiapiv1tail
*/

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	lokiclient "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki/internal/lokiclient"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	readyTimeout time.Duration = 3 * time.Second
	readyLoop    int           = 3
	readySleep   time.Duration = 10 * time.Second
	lokiLimit    int           = 100
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lokisource_hits_total",
		Help: "Total lines that were read.",
	},
	[]string{"source"})

type LokiAuthConfiguration struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type LokiConfiguration struct {
	URL                               string                `yaml:"url"`    // Loki url
	Prefix                            string                `yaml:"prefix"` // Loki prefix
	Query                             string                `yaml:"query"`  // LogQL query
	Limit                             int                   `yaml:"limit"`  // Limit of logs to read
	DelayFor                          time.Duration         `yaml:"delay_for"`
	Since                             time.Duration         `yaml:"since"`
	Headers                           map[string]string     `yaml:"headers"`        // HTTP headers for talking to Loki
	WaitForReady                      time.Duration         `yaml:"wait_for_ready"` // Retry interval, default is 10 seconds
	Auth                              LokiAuthConfiguration `yaml:"auth"`
	MaxFailureDuration                time.Duration         `yaml:"max_failure_duration"` // Max duration of failure before stopping the source
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type LokiSource struct {
	Config LokiConfiguration

	Client *lokiclient.LokiClient

	logger        *log.Entry
	lokiWebsocket string
}

func (l *LokiSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (l *LokiSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (l *LokiSource) UnmarshalConfig(yamlConfig []byte) error {
	err := yaml.UnmarshalStrict(yamlConfig, &l.Config)
	if err != nil {
		return fmt.Errorf("cannot parse loki acquisition configuration: %w", err)
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

func (l *LokiSource) Configure(config []byte, logger *log.Entry) error {
	l.Config = LokiConfiguration{}
	l.logger = logger
	err := l.UnmarshalConfig(config)
	if err != nil {
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

func (l *LokiSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	l.logger = logger
	l.Config = LokiConfiguration{}
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

	if max_failure_duration := params.Get("max_failure_duration"); max_failure_duration != "" {
		duration, err := time.ParseDuration(max_failure_duration)
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
		l.Config.LogLevel = &level
		l.logger.Logger.SetLevel(level)
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

func (l *LokiSource) GetMode() string {
	return l.Config.Mode
}

func (l *LokiSource) GetName() string {
	return "loki"
}

// OneShotAcquisition reads a set of file and returns when done
func (l *LokiSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	l.logger.Debug("Loki one shot acquisition")
	l.Client.SetTomb(t)
	readyCtx, cancel := context.WithTimeout(context.Background(), l.Config.WaitForReady)
	defer cancel()
	err := l.Client.Ready(readyCtx)
	if err != nil {
		return fmt.Errorf("loki is not ready: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := l.Client.QueryRange(ctx, false)

	for {
		select {
		case <-t.Dying():
			l.logger.Debug("Loki one shot acquisition stopped")
			cancel()
			return nil
		case resp, ok := <-c:
			if !ok {
				l.logger.Info("Loki acquisition done, chan closed")
				cancel()
				return nil
			}
			for _, stream := range resp.Data.Result {
				for _, entry := range stream.Entries {
					l.readOneEntry(entry, l.Config.Labels, out)
				}
			}
		}
	}
}

func (l *LokiSource) readOneEntry(entry lokiclient.Entry, labels map[string]string, out chan types.Event) {
	ll := types.Line{}
	ll.Raw = entry.Line
	ll.Time = entry.Timestamp
	ll.Src = l.Config.URL
	ll.Labels = labels
	ll.Process = true
	ll.Module = l.GetName()

	linesRead.With(prometheus.Labels{"source": l.Config.URL}).Inc()
	expectMode := types.LIVE
	if l.Config.UseTimeMachine {
		expectMode = types.TIMEMACHINE
	}
	out <- types.Event{
		Line:       ll,
		Process:    true,
		Type:       types.LOG,
		ExpectMode: expectMode,
	}
}

func (l *LokiSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	l.Client.SetTomb(t)
	readyCtx, cancel := context.WithTimeout(context.Background(), l.Config.WaitForReady)
	defer cancel()
	err := l.Client.Ready(readyCtx)
	if err != nil {
		return fmt.Errorf("loki is not ready: %w", err)
	}
	ll := l.logger.WithField("websocket_url", l.lokiWebsocket)
	t.Go(func() error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		respChan := l.Client.QueryRange(ctx, true)
		if err != nil {
			ll.Errorf("could not start loki tail: %s", err)
			return fmt.Errorf("while starting loki tail: %w", err)
		}
		for {
			select {
			case resp, ok := <-respChan:
				if !ok {
					ll.Warnf("loki channel closed")
					return err
				}
				for _, stream := range resp.Data.Result {
					for _, entry := range stream.Entries {
						l.readOneEntry(entry, l.Config.Labels, out)
					}
				}
			case <-t.Dying():
				return nil
			}
		}
	})
	return nil
}

func (l *LokiSource) CanRun() error {
	return nil
}

func (l *LokiSource) GetUuid() string {
	return l.Config.UniqueId
}

func (l *LokiSource) Dump() interface{} {
	return l
}

// SupportedModes returns the supported modes by the acquisition module
func (l *LokiSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}
