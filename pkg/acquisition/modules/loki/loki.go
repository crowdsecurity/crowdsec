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
	lokiLimit    int           = 100
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lokisource_hits_total",
		Help: "Total lines that were read.",
	},
	[]string{"source"})

type LokiConfiguration struct {
	URL                               string        `yaml:"url"`   // Loki url
	Query                             string        `yaml:"query"` // LogQL query
	DelayFor                          time.Duration `yaml:"delay_for"`
	Since                             time.Duration `yaml:"since"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type LokiSource struct {
	Config        LokiConfiguration
	logger        *log.Entry
	lokiWebsocket string
	lokiReady     string
	dialer        *websocket.Dialer
}

func (l *LokiSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (l *LokiSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (l *LokiSource) Configure(config []byte, logger *log.Entry) error {
	l.Config = LokiConfiguration{}
	l.logger = logger
	err := yaml.UnmarshalStrict(config, &l.Config)
	if err != nil {
		return errors.Wrap(err, "Cannot parse LokiAcquisition configuration")
	}
	l.dialer = &websocket.Dialer{}
	err = l.buildUrl()
	if err != nil {
		return errors.Wrap(err, "Cannot build Loki url")
	}

	return nil
}

func (l *LokiSource) buildUrl() error {
	u, err := url.Parse(l.Config.URL)
	if err != nil {
		return errors.Wrap(err, "Cannot parse Loki URL : "+l.Config.URL)
	}
	l.lokiReady = fmt.Sprintf("%s://%s/ready", u.Scheme, u.Host)

	buff := bytes.Buffer{}
	switch u.Scheme {
	case "http":
		buff.WriteString("ws")
	case "https":
		buff.WriteString("wss")
	default:
		return fmt.Errorf("unknown scheme : %s", u.Scheme)
	}
	buff.WriteString("://")
	buff.WriteString(u.Host)
	if u.Path == "" {
		buff.WriteString("/loki/api/v1/tail")
	} else {
		buff.WriteString(u.Path)
	}
	buff.WriteByte('?')
	params := url.Values{}
	params.Add("query", l.Config.Query)
	params.Add("limit", fmt.Sprintf("%d", lokiLimit))
	if l.Config.DelayFor != 0 {
		params.Add("delay_for", fmt.Sprintf("%d", int64(l.Config.DelayFor.Seconds())))
	}
	start := time.Now() // FIXME config
	if l.Config.Since != 0 {
		start = start.Add(-l.Config.Since)
	}
	params.Add("start", fmt.Sprintf("%d", start.UnixNano()))
	buff.WriteString(params.Encode())
	l.lokiWebsocket = buff.String()
	return nil
}

func (l *LokiSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	l.logger = logger
	l.Config = LokiConfiguration{}
	l.Config.Mode = configuration.CAT_MODE
	l.Config.Labels = labels

	if !strings.HasPrefix(dsn, "loki://") {
		return fmt.Errorf("invalid DSN %s for loki source, must start with loki://", dsn)
	}
	// FIXME DSN parsing
	return nil
}

func (l *LokiSource) GetMode() string {
	return l.Config.Mode
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
	l.readOneTail(resp, out)
	return nil
}

func (l *LokiSource) readOneTail(resp Tail, out chan types.Event) {
	for _, stream := range resp.Streams {
		for _, entry := range stream.Entries {

			ll := types.Line{}
			ll.Raw = entry.Line
			ll.Time = entry.Timestamp
			ll.Src = l.Config.URL
			ll.Labels = stream.Stream
			ll.Process = true
			ll.Module = l.GetName()

			linesRead.With(prometheus.Labels{"source": l.Config.URL}).Inc()
			out <- types.Event{
				Line:       ll,
				Process:    true,
				Type:       types.LOG,
				ExpectMode: leaky.TIMEMACHINE,
			}
		}
	}
}

func (l *LokiSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	err := l.ready()
	if err != nil {
		return errors.Wrap(err, "error while getting OneShotAcquisition")
	}
	t.Go(func() error {
		for {
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
			for { // draining the websocket
				err = c.ReadJSON(&resp)
				if err != nil {
					return errors.Wrap(err, "OneShotAcquisition error while reading JSON websocket")
				}
				l.readOneTail(resp, out)
			}
		}
		return nil
	})
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
