package loki

/*
https://grafana.com/docs/loki/latest/api/#get-lokiapiv1tail
*/

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

const (
	readyTimeout time.Duration = 3 * time.Second
	readyLoop    int           = 3
	readySleep   time.Duration = 10 * time.Second
)

type LokiConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	URL                               string // websocket url
	Query                             string // LogQL query
}

type LokiSource struct {
	config        LokiConfiguration
	logger        *log.Entry
	lokiWebsocket string
	lokiReady     string
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
	l.lokiWebsocket, l.lokiReady, err = websocketFromUrl(lokiConfig.URL)
	if err != nil {
		return errors.Wrap(err, "Cannot parse Loki url")
	}

	return nil
}

func websocketFromUrl(lokiUrl string) (string, string, error) {
	u, err := url.Parse(lokiUrl)
	if err != nil {
		return "", "", errors.Wrap(err, "Cannot parse Loki URL")
	}

	buff := bytes.Buffer{}
	switch u.Scheme {
	case "http":
		buff.WriteString("ws")
	case "https":
		buff.WriteString("wss")
	default:
		return "", "", fmt.Errorf("unknown scheme : %s", u.Scheme)
	}
	buff.WriteString("://")
	buff.WriteString(u.Host)
	if u.Path == "" {
		buff.WriteString("/loki/api/v1/tail")
	} else {
		buff.WriteString(u.Path)
	}
	return buff.String(), fmt.Sprintf("%s://%s/ready", u.Scheme, u.Host), nil
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

func (l *LokiSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	err := l.ready()
	if err != nil {
		return errors.Wrap(err, "error while getting OneShotAcquisition")
	}
	ctx, cancel := context.WithTimeout(context.TODO(), readyTimeout)
	defer cancel()
	header := &http.Header{}
	c, res, err := l.dialer.DialContext(ctx, l.lokiWebsocket, *header)
	if err != nil {
		buf, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("loki websocket (%s) error %v : %s", l.lokiWebsocket, err, string(buf))
	}
	defer c.Close()
	var resp Tail
	err = c.ReadJSON(&resp)
	if err != nil {
		return errors.Wrap(err, "OneShotAcquisition error while reading JSON websocket")
	}
	ll := types.Line{}
	ll.Raw = resp.Streams[0].Entries[0].Line
	ll.Time = resp.Streams[0].Entries[0].Timestamp
	ll.Src = l.lokiReady
	ll.Labels = resp.Streams[0].Stream
	ll.Process = true
	ll.Module = l.GetName()

	out <- types.Event{
		Line:       ll,
		Process:    true,
		Type:       types.LOG,
		ExpectMode: leaky.TIMEMACHINE,
	}
	return nil
}

func (l *LokiSource) StreamingAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (l *LokiSource) CanRun() error {
	return nil // it's ok, even BSD can use Loki
}

func (l *LokiSource) Dump() interface{} {
	return l
}

func (l *LokiSource) ready() error {
	client := &http.Client{
		Timeout: readyTimeout,
	}

	for i := 0; i < readyLoop; i++ {
		resp, err := client.Get(l.lokiReady)
		if err != nil {
			return errors.Wrap(err, "Test Loki services for readiness")
		}
		if resp.StatusCode == 200 {
			return nil
		} else {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return errors.Wrap(err, "can't read body while testing Loki readiness")
			}
			err = resp.Body.Close()
			if err != nil {
				return err
			}
			l.logger.Println("Loki is not ready :", string(body))
			time.Sleep(10 * time.Second)
		}
	}

	return fmt.Errorf("Loki service %s is not ready", l.lokiReady)
}
