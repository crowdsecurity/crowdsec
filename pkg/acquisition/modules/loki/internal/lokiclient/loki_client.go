package lokiclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type LokiClient struct {
	Logger *log.Entry

	config                Config
	t                     *tomb.Tomb
	fail_start            time.Time
	currentTickerInterval time.Duration
}

type Config struct {
	LokiURL    string
	LokiPrefix string
	Query      string
	Headers    map[string]string

	Username string
	Password string

	Since time.Duration
	Until time.Duration

	FailMaxDuration time.Duration

	DelayFor int
	Limit    int
}

func updateURI(uri string, lq LokiQueryRangeResponse, infinite bool) string {
	u, _ := url.Parse(uri)
	queryParams := u.Query()

	if len(lq.Data.Result) > 0 {
		lastTs := lq.Data.Result[0].Entries[len(lq.Data.Result[0].Entries)-1].Timestamp
		// +1 the last timestamp to avoid getting the same result again.
		queryParams.Set("start", strconv.Itoa(int(lastTs.UnixNano()+1)))
	}

	if infinite {
		queryParams.Set("end", strconv.Itoa(int(time.Now().UnixNano())))
	}

	u.RawQuery = queryParams.Encode()
	return u.String()
}

func (lc *LokiClient) SetTomb(t *tomb.Tomb) {
	lc.t = t
}

func (lc *LokiClient) resetFailStart() {
	if !lc.fail_start.IsZero() {
		log.Infof("loki is back after %s", time.Since(lc.fail_start))
	}
	lc.fail_start = time.Time{}
}
func (lc *LokiClient) shouldRetry() bool {
	if lc.fail_start.IsZero() {
		lc.Logger.Warningf("loki is not available, will retry for %s", lc.config.FailMaxDuration)
		lc.fail_start = time.Now()
		return true
	}
	if time.Since(lc.fail_start) > lc.config.FailMaxDuration {
		lc.Logger.Errorf("loki didn't manage to recover after %s, giving up", lc.config.FailMaxDuration)
		return false
	}
	return true
}

func (lc *LokiClient) increaseTicker(ticker *time.Ticker) {
	maxTicker := 10 * time.Second
	if lc.currentTickerInterval < maxTicker {
		lc.currentTickerInterval *= 2
		if lc.currentTickerInterval > maxTicker {
			lc.currentTickerInterval = maxTicker
		}
		ticker.Reset(lc.currentTickerInterval)
	}
}

func (lc *LokiClient) decreaseTicker(ticker *time.Ticker) {
	minTicker := 100 * time.Millisecond
	if lc.currentTickerInterval != minTicker {
		lc.currentTickerInterval = minTicker
		ticker.Reset(lc.currentTickerInterval)
	}
}

func (lc *LokiClient) queryRange(uri string, ctx context.Context, c chan *LokiQueryRangeResponse, infinite bool) error {
	lc.currentTickerInterval = 100 * time.Millisecond
	ticker := time.NewTicker(lc.currentTickerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-lc.t.Dying():
			return lc.t.Err()
		case <-ticker.C:
			resp, err := http.Get(uri)
			if err != nil {
				if ok := lc.shouldRetry(); !ok {
					return errors.Wrapf(err, "error querying range")
				} else {
					lc.increaseTicker(ticker)
					continue
				}
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if ok := lc.shouldRetry(); !ok {
					return errors.Wrapf(err, "bad HTTP response code: %d: %s", resp.StatusCode, string(body))
				} else {
					lc.increaseTicker(ticker)
					continue
				}
			}

			var lq LokiQueryRangeResponse
			if err := json.NewDecoder(resp.Body).Decode(&lq); err != nil {
				resp.Body.Close()
				if ok := lc.shouldRetry(); !ok {
					return errors.Wrapf(err, "error decoding Loki response")
				} else {
					lc.increaseTicker(ticker)
					continue
				}
			}
			resp.Body.Close()
			lc.Logger.Tracef("Got response: %+v", lq)
			c <- &lq
			lc.resetFailStart()
			if !infinite && (len(lq.Data.Result) == 0 || len(lq.Data.Result[0].Entries) < lc.config.Limit) {
				lc.Logger.Infof("Got less than %d results (%d), stopping", lc.config.Limit, len(lq.Data.Result))
				close(c)
				return nil
			}
			if len(lq.Data.Result) > 0 {
				lc.Logger.Debugf("(timer:%v) %d results / %d entries result[0] (uri:%s)", lc.currentTickerInterval, len(lq.Data.Result), len(lq.Data.Result[0].Entries), uri)
			} else {
				lc.Logger.Debugf("(timer:%v) no results (uri:%s)", lc.currentTickerInterval, uri)
			}
			if infinite {
				if len(lq.Data.Result) > 0 { //as long as we get results, we keep lowest ticker
					lc.decreaseTicker(ticker)
				} else {
					lc.increaseTicker(ticker)
				}
			}

			uri = updateURI(uri, lq, infinite)
		}
	}
}

func (lc *LokiClient) getURLFor(endpoint string, params map[string]string) string {
	u, err := url.Parse(lc.config.LokiURL)
	if err != nil {
		return ""
	}
	queryParams := u.Query()
	for k, v := range params {
		queryParams.Set(k, v)
	}
	u.RawQuery = queryParams.Encode()

	u.Path, err = url.JoinPath(lc.config.LokiPrefix, u.Path, endpoint)

	if err != nil {
		return ""
	}

	if endpoint == "loki/api/v1/tail" {
		if u.Scheme == "http" {
			u.Scheme = "ws"
		} else {
			u.Scheme = "wss"
		}
	}

	return u.String()
}

func (lc *LokiClient) Ready(ctx context.Context) error {
	tick := time.NewTicker(500 * time.Millisecond)
	url := lc.getURLFor("ready", nil)
	for {
		select {
		case <-ctx.Done():
			tick.Stop()
			return ctx.Err()
		case <-lc.t.Dying():
			tick.Stop()
			return lc.t.Err()
		case <-tick.C:
			lc.Logger.Debug("Checking if Loki is ready")
			resp, err := http.Get(url)
			if err != nil {
				lc.Logger.Warnf("Error checking if Loki is ready: %s", err)
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				lc.Logger.Debugf("Loki is not ready, status code: %d", resp.StatusCode)
				continue
			}
			lc.Logger.Info("Loki is ready")
			return nil
		}
	}
}

func (lc *LokiClient) Tail(ctx context.Context) (chan *LokiResponse, error) {
	responseChan := make(chan *LokiResponse)
	dialer := &websocket.Dialer{}
	u := lc.getURLFor("loki/api/v1/tail", map[string]string{
		"limit":     strconv.Itoa(lc.config.Limit),
		"start":     strconv.Itoa(int(time.Now().Add(-lc.config.Since).UnixNano())),
		"query":     lc.config.Query,
		"delay_for": strconv.Itoa(lc.config.DelayFor),
	})

	lc.Logger.Debugf("Since: %s (%s)", lc.config.Since, time.Now().Add(-lc.config.Since))

	if lc.config.Username != "" || lc.config.Password != "" {
		dialer.Proxy = func(req *http.Request) (*url.URL, error) {
			req.SetBasicAuth(lc.config.Username, lc.config.Password)
			return nil, nil
		}
	}

	requestHeader := http.Header{}
	for k, v := range lc.config.Headers {
		requestHeader.Add(k, v)
	}
	requestHeader.Set("User-Agent", "Crowdsec "+cwversion.VersionStr())
	lc.Logger.Infof("Connecting to %s", u)
	conn, _, err := dialer.Dial(u, requestHeader)

	if err != nil {
		lc.Logger.Errorf("Error connecting to websocket, err: %s", err)
		return responseChan, fmt.Errorf("error connecting to websocket")
	}

	lc.t.Go(func() error {
		for {
			jsonResponse := &LokiResponse{}
			err = conn.ReadJSON(jsonResponse)

			if err != nil {
				lc.Logger.Errorf("Error reading from websocket: %s", err)
				return fmt.Errorf("websocket error: %w", err)
			}

			responseChan <- jsonResponse
		}
	})

	return responseChan, nil
}

func (lc *LokiClient) QueryRange(ctx context.Context, infinite bool) chan *LokiQueryRangeResponse {
	url := lc.getURLFor("loki/api/v1/query_range", map[string]string{
		"query":     lc.config.Query,
		"start":     strconv.Itoa(int(time.Now().Add(-lc.config.Since).UnixNano())),
		"end":       strconv.Itoa(int(time.Now().UnixNano())),
		"limit":     strconv.Itoa(lc.config.Limit),
		"direction": "forward",
	})

	c := make(chan *LokiQueryRangeResponse)

	lc.Logger.Debugf("Since: %s (%s)", lc.config.Since, time.Now().Add(-lc.config.Since))

	requestHeader := http.Header{}
	for k, v := range lc.config.Headers {
		requestHeader.Add(k, v)
	}

	if lc.config.Username != "" || lc.config.Password != "" {
		requestHeader.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(lc.config.Username+":"+lc.config.Password)))
	}

	requestHeader.Set("User-Agent", "Crowdsec "+cwversion.VersionStr())
	lc.Logger.Infof("Connecting to %s", url)
	lc.t.Go(func() error {
		return lc.queryRange(url, ctx, c, infinite)
	})
	return c
}

func NewLokiClient(config Config) *LokiClient {
	return &LokiClient{Logger: log.WithField("component", "lokiclient"), config: config}
}
