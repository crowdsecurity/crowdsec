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
	"io"
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
	Since                             timestamp         `yaml:"since"`
	TenantID                          string            `yaml:"tenant_id"`
	Headers                           map[string]string `yaml:"headers"`        // HTTP headers for talking to Loki
	WaitForReady                      time.Duration     `yaml:"wait_for_ready"` // Retry interval, default is 10 seconds
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
	if l.Config.WaitForReady == 0 {
		l.Config.WaitForReady = 10 * time.Second
	}
	if l.Config.Mode == "" {
		l.Config.Mode = configuration.TAIL_MODE
	}
	u, err := url.Parse(l.Config.URL)
	if err != nil {
		return err
	}
	if l.Config.Since.IsZero() {
		l.Config.Since = timestamp(time.Now())
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
	if l.Config.Query == "" {
		return errors.New("Loki query is mandatory")
	}
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
	start := time.Time(l.Config.Since)
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
	if w := params.Get("wait_for_ready"); w != "" {
		l.Config.WaitForReady, err = time.ParseDuration(w)
		if err != nil {
			return err
		}
	} else {
		l.Config.WaitForReady = 10 * time.Second
	}
	if d := params.Get("delay_for"); d != "" {
		delayFor, err := time.ParseDuration(d)
		if err != nil {
			return err
		}
		l.Config.DelayFor = delayFor
	}
	if s := params.Get("since"); s != "" {
		err = yaml.Unmarshal([]byte(s), &l.Config.Since)
		if err != nil {
			return errors.Wrap(err, "can't parse since in DSB configuration")
		}
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

// OneShotAcquisition reads a set of file and returns when done
func (l *LokiSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	err := l.ready()
	if err != nil {
		return errors.Wrap(err, "error while getting OneShotAcquisition")
	}

	// See https://grafana.com/docs/loki/latest/api/#get-lokiapiv1query_range
	params := &url.Values{}
	params.Set("query", l.Config.Query)
	params.Set("direction", "forward") // FIXME
	params.Set("limit", fmt.Sprintf("%d", lokiLimit))
	params.Set("end", time.Now().Format(time.RFC3339))
	start := time.Time(l.Config.Since)

	var lq LokiQuery
	defer t.Kill(nil)
	defer l.logger.Info("Loki queried")

	for {
		params.Set("start", start.Format(time.RFC3339))
		url := fmt.Sprintf("%s/loki/api/v1/query_range?%s",
			l.Config.URL,
			params.Encode())
		logger := l.logger.WithField("url", url)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			logger.WithError(err).Error("Loki NewRequest error")
			return errors.Wrap(err, "Loki error while build new request")
		}
		req.Header = l.header

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.WithError(err).Error("http error")
			return errors.Wrap(err, "Error while querying loki")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			msg, _ := io.ReadAll(resp.Body)
			logger.WithField("status", resp.StatusCode).WithField("body", string(msg)).Error("loki error")
			return fmt.Errorf("Loki query return bad status : %d", resp.StatusCode)
		}
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&lq)
		if err != nil {
			return errors.Wrap(err, "can't parse JSON loki response")
		}
		if len(lq.Data.Result) == 0 {
			return nil
		}
		for _, result := range lq.Data.Result {
			if len(result.Values) == 0 {
				return nil
			}
			start = result.Values[0].Timestamp
			logger.WithField("stream", result.Stream).Debug("Results", len(result.Values))
			for _, entry := range result.Values {
				l.readOneEntry(entry, result.Stream, out)
			}
			if len(result.Values) <= lokiLimit {
				return nil
			}
		}
	}
	return nil
}

func (l *LokiSource) readOneTail(resp Tail, out chan types.Event) {
	for _, stream := range resp.Streams {
		for _, entry := range stream.Entries {
			l.readOneEntry(entry, stream.Stream, out)
		}
	}
}

func (l *LokiSource) readOneEntry(entry Entry, labels map[string]string, out chan types.Event) {
	ll := types.Line{}
	ll.Raw = entry.Line
	ll.Time = entry.Timestamp
	ll.Src = l.Config.URL
	ll.Labels = labels
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
				err = json.Unmarshal(msg, &resp)
				if err != nil {
					return errors.Wrap(err, "OneShotAcquisition error while reading JSON websocket")
				}
				l.logger.WithField("type", t).WithField("message", resp).Debug("Message receveid")
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
		Timeout: l.Config.WaitForReady,
	}

	req, err := http.NewRequest("GET", l.lokiReady, nil)
	if err != nil {
		return err
	}
	req.Header = l.header

	for i := 0; i < int(l.Config.WaitForReady/time.Second); i++ {
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
			defer resp.Body.Close()
			l.logger.WithField("status", resp.StatusCode).WithField("bofy", string(body)).Info("Loki is not ready")
			time.Sleep(time.Second)
		}
	}

	return fmt.Errorf("Loki service %s is not ready", l.lokiReady)
}

//SupportedModes returns the supported modes by the acquisition module
func (l *LokiSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}
