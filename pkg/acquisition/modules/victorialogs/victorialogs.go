package victorialogs

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs/internal/vlclient"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	defaultLimit int = 100
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_victorialogssource_hits_total",
		Help: "Total lines that were read.",
	},
	[]string{"source"})

type VLAuthConfiguration struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type VLConfiguration struct {
	URL                               string              `yaml:"url"`    // VictoriaLogs url
	Prefix                            string              `yaml:"prefix"` // VictoriaLogs prefix
	Query                             string              `yaml:"query"`  // LogsQL query
	Limit                             int                 `yaml:"limit"`  // Limit of logs to read
	Since                             time.Duration       `yaml:"since"`
	Headers                           map[string]string   `yaml:"headers"`        // HTTP headers for talking to VictoriaLogs
	WaitForReady                      time.Duration       `yaml:"wait_for_ready"` // Retry interval, default is 10 seconds
	Auth                              VLAuthConfiguration `yaml:"auth"`
	MaxFailureDuration                time.Duration       `yaml:"max_failure_duration"` // Max duration of failure before stopping the source
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type VLSource struct {
	metricsLevel int
	Config       VLConfiguration

	Client *vlclient.VLClient

	logger *log.Entry
}

func (l *VLSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (l *VLSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (l *VLSource) UnmarshalConfig(yamlConfig []byte) error {
	err := yaml.UnmarshalStrict(yamlConfig, &l.Config)
	if err != nil {
		return fmt.Errorf("cannot parse VictoriaLogs acquisition configuration: %w", err)
	}

	if l.Config.Query == "" {
		return errors.New("VictoriaLogs query is mandatory")
	}

	if l.Config.WaitForReady == 0 {
		l.Config.WaitForReady = 10 * time.Second
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
		l.Config.Limit = defaultLimit
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

func (l *VLSource) Configure(config []byte, logger *log.Entry, metricsLevel int) error {
	l.Config = VLConfiguration{}
	l.logger = logger
	l.metricsLevel = metricsLevel
	err := l.UnmarshalConfig(config)
	if err != nil {
		return err
	}

	l.logger.Infof("Since value: %s", l.Config.Since.String())

	clientConfig := vlclient.Config{
		URL:             l.Config.URL,
		Headers:         l.Config.Headers,
		Limit:           l.Config.Limit,
		Query:           l.Config.Query,
		Since:           l.Config.Since,
		Username:        l.Config.Auth.Username,
		Password:        l.Config.Auth.Password,
		FailMaxDuration: l.Config.MaxFailureDuration,
	}

	l.Client = vlclient.NewVLClient(clientConfig)
	l.Client.Logger = logger.WithFields(log.Fields{"component": "victorialogs-client", "source": l.Config.URL})
	return nil
}

func (l *VLSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	l.logger = logger
	l.Config = VLConfiguration{}
	l.Config.Mode = configuration.CAT_MODE
	l.Config.Labels = labels
	l.Config.UniqueId = uuid

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

	clientConfig := vlclient.Config{
		URL:      l.Config.URL,
		Headers:  l.Config.Headers,
		Limit:    l.Config.Limit,
		Query:    l.Config.Query,
		Since:    l.Config.Since,
		Username: l.Config.Auth.Username,
		Password: l.Config.Auth.Password,
	}

	l.Client = vlclient.NewVLClient(clientConfig)
	l.Client.Logger = logger.WithFields(log.Fields{"component": "victorialogs-client", "source": l.Config.URL})

	return nil
}

func (l *VLSource) GetMode() string {
	return l.Config.Mode
}

func (l *VLSource) GetName() string {
	return "victorialogs"
}

// OneShotAcquisition reads a set of file and returns when done
func (l *VLSource) OneShotAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	l.logger.Debug("VictoriaLogs one shot acquisition")
	l.Client.SetTomb(t)
	readyCtx, cancel := context.WithTimeout(ctx, l.Config.WaitForReady)
	defer cancel()
	err := l.Client.Ready(readyCtx)
	if err != nil {
		return fmt.Errorf("VictoriaLogs is not ready: %w", err)
	}

	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	respChan, err := l.getResponseChan(ctx, false)
	if err != nil {
		return fmt.Errorf("error when starting acquisition: %w", err)
	}

	for {
		select {
		case <-t.Dying():
			l.logger.Debug("VictoriaLogs one shot acquisition stopped")
			return nil
		case resp, ok := <-respChan:
			if !ok {
				l.logger.Info("VictoriaLogs acquisition completed")
				return nil
			}
			l.readOneEntry(resp, l.Config.Labels, out)
		}
	}
}

func (l *VLSource) readOneEntry(entry *vlclient.Log, labels map[string]string, out chan types.Event) {
	ll := types.Line{}
	ll.Raw = entry.Message
	ll.Time = entry.Time
	ll.Src = l.Config.URL
	ll.Labels = labels
	ll.Process = true
	ll.Module = l.GetName()

	if l.metricsLevel != configuration.METRICS_NONE {
		linesRead.With(prometheus.Labels{"source": l.Config.URL}).Inc()
	}
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

func (l *VLSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	l.Client.SetTomb(t)
	readyCtx, cancel := context.WithTimeout(ctx, l.Config.WaitForReady)
	defer cancel()
	err := l.Client.Ready(readyCtx)
	if err != nil {
		return fmt.Errorf("VictoriaLogs is not ready: %w", err)
	}

	lctx, clientCancel := context.WithCancel(ctx)
	//Don't defer clientCancel(), the client outlives this function call

	t.Go(func() error {
		<-t.Dying()
		clientCancel()
		return nil
	})

	t.Go(func() error {
		respChan, err := l.getResponseChan(lctx, true)
		if err != nil {
			clientCancel()
			l.logger.Errorf("could not start VictoriaLogs tail: %s", err)
			return fmt.Errorf("while starting VictoriaLogs tail: %w", err)
		}
		for {
			select {
			case resp, ok := <-respChan:
				if !ok {
					l.logger.Warnf("VictoriaLogs channel closed")
					clientCancel()
					return err
				}
				l.readOneEntry(resp, l.Config.Labels, out)
			case <-t.Dying():
				clientCancel()
				return nil
			}
		}
	})
	return nil
}

func (l *VLSource) getResponseChan(ctx context.Context, infinite bool) (chan *vlclient.Log, error) {
	var (
		respChan chan *vlclient.Log
		err      error
	)

	if l.Config.Mode == configuration.TAIL_MODE {
		respChan, err = l.Client.Tail(ctx)
		if err != nil {
			l.logger.Errorf("could not start VictoriaLogs tail: %s", err)
			return respChan, fmt.Errorf("while starting VictoriaLogs tail: %w", err)
		}
	} else {
		respChan = l.Client.QueryRange(ctx, infinite)
	}
	return respChan, err
}

func (l *VLSource) CanRun() error {
	return nil
}

func (l *VLSource) GetUuid() string {
	return l.Config.UniqueId
}

func (l *VLSource) Dump() interface{} {
	return l
}

// SupportedModes returns the supported modes by the acquisition module
func (l *VLSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}
