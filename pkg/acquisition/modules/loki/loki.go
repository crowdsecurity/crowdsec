package loki

/*
https://grafana.com/docs/loki/latest/api/#get-lokiapiv1tail
*/

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
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
	URL                               string            `yaml:"url"`   // Loki url
	Query                             string            `yaml:"query"` // LogQL query
	DelayFor                          time.Duration     `yaml:"delay_for"`
	Since                             time.Duration     `yaml:"since"`
	TenantID                          string            `yaml:"tenant_id"`
	Headers                           map[string]string `yaml:"headers"` // HTTP headers for talking to Loki
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type LokiSource struct {
	Config        LokiConfiguration
	logger        *log.Entry
	lokiWebsocket string
	lokiReady     string
	dialer        *websocket.Dialer
	header        http.Header
	auth          *url.Userinfo
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
	u, err := url.Parse(l.Config.URL)
	if err != nil {
		return err
	}
	if u.User != nil {
		l.auth = u.User
	}
	err = l.buildUrl()
	if err != nil {
		return errors.Wrap(err, "Cannot build Loki url")
	}
	err = l.prepareConfig()
	if err != nil {
		return errors.Wrap(err, "Cannot prepare Loki config")
	}
	return nil
}

func (l *LokiSource) prepareConfig() error {
	l.dialer = &websocket.Dialer{}
	l.header = http.Header{}
	if l.Config.TenantID != "" {
		l.header.Set("X-Scope-OrgID", l.Config.TenantID)
	}
	l.header.Set("User-Agent", "Crowdsec "+cwversion.Version)
	for k, v := range l.Config.Headers {
		l.header.Set(k, v)
	}
	if l.auth != nil {
		l.header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(l.auth.String())))
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
	if l.Config.Query != "" {
		params.Add("query", l.Config.Query)
	}
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
	l.logger.Info("Websocket url : ", l.lokiWebsocket)
	return nil
}

func (l *LokiSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	l.logger = logger
	l.Config = LokiConfiguration{}
	l.Config.Mode = configuration.CAT_MODE
	l.Config.Labels = labels

	u, err := url.Parse(dsn)
	if err != nil {
		return errors.Wrap(err, "can't parse dsn configuration : "+dsn)
	}
	if u.Scheme != "loki" {
		return fmt.Errorf("invalid DSN %s for loki source, must start with loki://", dsn)
	}
	if u.Host == "" {
		return errors.New("Empty loki host")
	}
	scheme := "https"
	// FIXME how can use http with container, in a private network?
	if u.Host == "localhost" || u.Host == "127.0.0.1" || u.Host == "[::1]" {
		scheme = "http"
	}
	if u.User != nil {
		l.auth = u.User
	}
	l.Config.URL = fmt.Sprintf("%s://%s", scheme, u.Host)
	params := u.Query()
	if q := params.Get("query"); q != "" {
		l.Config.Query = q
	}
	if d := params.Get("delay_for"); d != "" {
		delayFor, err := time.ParseDuration(d)
		if err != nil {
			return err
		}
		l.Config.DelayFor = delayFor
	}
	if s := params.Get("since"); s != "" {
		since, err := time.ParseDuration(s)
		if err != nil {
			return errors.Wrap(err, "can't parse since in DSB configuration")
		}
		l.Config.Since = since
	}
	l.Config.TenantID = params.Get("tenantID")

	err = l.buildUrl()
	if err != nil {
		return errors.Wrap(err, "Cannot build Loki url from DSN")
	}
	err = l.prepareConfig()
	if err != nil {
		return errors.Wrap(err, "Cannot prepare Loki from DSN")
	}

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
	c, res, err := l.dialer.DialContext(ctx, l.lokiWebsocket, l.header)
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
		return errors.Wrap(err, "error while getting StreamingAcquisition")
	}
	t.Go(func() error {
		for {
			ctx, cancel := context.WithTimeout(context.TODO(), readyTimeout)
			defer cancel()
			c, res, err := l.dialer.DialContext(ctx, l.lokiWebsocket, l.header)
			if err != nil {
				buf, err2 := ioutil.ReadAll(res.Body)
				if err2 == nil {
					return fmt.Errorf("loki websocket (%s) error %v : %s", l.lokiWebsocket, err, string(buf))
				}
				return err2
			}
			defer c.Close()
			var resp Tail
			for { // draining the websocket
				t, msg, err := c.ReadMessage()
				if len(msg) == 0 {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				fmt.Println(t, string(msg))
				err = json.Unmarshal(msg, &resp)
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

	req, err := http.NewRequest("GET", l.lokiReady, nil)
	if err != nil {
		return err
	}
	req.Header = l.header

	for i := 0; i < readyLoop; i++ {
		resp, err := client.Do(req)
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
