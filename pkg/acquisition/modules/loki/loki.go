package loki

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type LokiConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	URL                               string // websocket url
}

type LokiSource struct {
	config        LokiConfiguration
	logger        *log.Entry
	lokiWebsocket string
	dialer        *websocket.Dialer
}

func (l *LokiSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (l *LokiSource) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func (l *LokiSource) Configure(config []byte, logger *log.Entry) error {
	lokiConfig := LokiConfiguration{}
	l.logger = logger
	err := yaml.UnmarshalStrict(config, &lokiConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse LokiAcquisition configuration")
	}
	l.dialer = &websocket.Dialer{}
	l.lokiWebsocket, err = websocketFromUrl(lokiConfig.URL)
	if err != nil {
		return errors.Wrap(err, "Cannot parse Loki url")
	}

	return nil
}

func websocketFromUrl(lokiUrl string) (string, error) {
	u, err := url.Parse(lokiUrl)
	if err != nil {
		return "", errors.Wrap(err, "Cannot parse Loki URL")
	}
	buff := bytes.Buffer{}
	switch u.Scheme {
	case "http":
		buff.WriteString("ws")
	case "https":
		buff.WriteString("wss")
	default:
		return "", fmt.Errorf("unknown scheme : %s", u.Scheme)
	}
	buff.WriteString("://")
	buff.WriteString(u.Host)
	if u.Path == "" {
		buff.WriteString("/loki/api/v1/tail")
	} else {
		buff.WriteString(u.Path)
	}
	return buff.String(), nil
}

func (l *LokiSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	l.logger = logger
	l.config = LokiConfiguration{}
	l.config.Mode = configuration.CAT_MODE
	l.config.Labels = labels

	if !strings.HasPrefix(dsn, "loki://") {
		return fmt.Errorf("invalid DSN %s for loki source, must start with loki://", dsn)
	}
	return nil
}

func (l *LokiSource) GetMode() string {
	return l.config.Mode
}

func (l *LokiSource) GetName() string {
	return "loki"
}

func (l *LokiSource) OneShotAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (l *LokiSource) StreamingAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (l *LokiSource) CanRun() error {
	return nil
}

func (l *LokiSource) Dump() interface{} {
	return l
}
