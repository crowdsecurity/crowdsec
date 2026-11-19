package lokiclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"maps"
)

type LokiClient struct {
	Logger *log.Entry

	config                Config
	t                     *tomb.Tomb
	failStart             time.Time
	currentTickerInterval time.Duration
	requestHeaders        map[string]string
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

	DelayFor     int
	Limit        int
	QueryDelay   time.Duration
	PollInterval time.Duration
}

func (lc *LokiClient) SetTomb(t *tomb.Tomb) {
	lc.t = t
}

func (lc *LokiClient) resetFailStart() {
	if !lc.failStart.IsZero() {
		log.Infof("loki is back after %s", time.Since(lc.failStart))
	}
	lc.failStart = time.Time{}
}

func (lc *LokiClient) shouldRetry() bool {
	if lc.failStart.IsZero() {
		lc.Logger.Warningf("loki is not available, will retry for %s", lc.config.FailMaxDuration)
		lc.failStart = time.Now()
		return true
	}
	if time.Since(lc.failStart) > lc.config.FailMaxDuration {
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
	lc.Logger.Debugf("Using url: %s for ready check", url)
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
			resp, err := lc.Get(ctx, url)
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
		"start":     strconv.FormatInt(time.Now().Add(-lc.config.Since).UnixNano(), 10),
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
	for k, v := range lc.requestHeaders {
		requestHeader.Add(k, v)
	}
	lc.Logger.Infof("Connecting to %s", u)

	conn, resp, err := dialer.Dial(u, requestHeader)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		lc.Logger.Errorf("Error connecting to websocket, err: %s", err)
		return responseChan, errors.New("error connecting to websocket")
	}

	lc.t.Go(func() error {
		defer conn.Close()
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
		"start":     strconv.FormatInt(time.Now().Add(-lc.config.Since).UnixNano(), 10),
		"end":       strconv.FormatInt(time.Now().UnixNano(), 10),
		"limit":     strconv.Itoa(lc.config.Limit),
		"direction": "forward",
	})

	c := make(chan *LokiQueryRangeResponse)

	lc.Logger.Debugf("Since: %s (%s)", lc.config.Since, time.Now().Add(-lc.config.Since))

	lc.Logger.Infof("Connecting to %s", url)
	lc.t.Go(func() error {
		return lc.readRange(ctx, url, c, infinite)
	})
	return c
}

// Get creates a wrapper for http.Get to be able to set headers and auth
func (lc *LokiClient) Get(ctx context.Context, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	for k, v := range lc.requestHeaders {
		request.Header.Add(k, v)
	}
	return http.DefaultClient.Do(request)
}

func NewLokiClient(config Config) *LokiClient {
	headers := make(map[string]string)
	maps.Copy(headers, config.Headers)
	if config.Username != "" || config.Password != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password))
	}
	headers["User-Agent"] = useragent.Default()
	return &LokiClient{Logger: log.WithField("component", "lokiclient"), config: config, requestHeaders: headers}
}
