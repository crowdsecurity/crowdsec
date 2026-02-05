package vlclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"maps"
)

type VLClient struct {
	Logger *log.Entry

	config                Config
	t                     *tomb.Tomb
	failStart             time.Time
	currentTickerInterval time.Duration
	requestHeaders        map[string]string

	client *http.Client
}

type Config struct {
	URL     string
	Prefix  string
	Query   string
	Headers map[string]string

	Username string
	Password string

	Since time.Duration

	FailMaxDuration time.Duration

	Limit int
}

func updateURI(uri string, newStart time.Time) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid VictoriaLogs URL %q: %w", uri, err)
	}

	queryParams := u.Query()

	if !newStart.IsZero() {
		// +1 the last timestamp to avoid getting the same result again.
		updatedStart := newStart.Add(1 * time.Nanosecond)
		queryParams.Set("start", updatedStart.Format(time.RFC3339Nano))
	}

	u.RawQuery = queryParams.Encode()

	return u.String(), nil
}

// newStart should be the desired start time for the tail query
// start_offset is computed from this
func updateTailURI(uri string, newStart time.Time) string {
	u, _ := url.Parse(uri)
	queryParams := u.Query()

	queryTime := time.Now()
	startOffset := 5000
	gracePeriod := 50*time.Millisecond

	if !newStart.IsZero() {
		if newStart.Before(queryTime) {
			startOffset = int((queryTime.Sub(newStart) + gracePeriod).Milliseconds())
		}
	} else {
	}
	queryParams.Set("start_offset", strconv.Itoa(startOffset))

	u.RawQuery = queryParams.Encode()

	return u.String()
}
func (lc *VLClient) SetTomb(t *tomb.Tomb) {
	lc.t = t
}

func (lc *VLClient) shouldRetry() bool {
	if lc.failStart.IsZero() {
		lc.Logger.Warningf("VictoriaLogs is not available, will retry for %s", lc.config.FailMaxDuration)
		lc.failStart = time.Now()

		return true
	}

	if time.Since(lc.failStart) > lc.config.FailMaxDuration {
		lc.Logger.Errorf("VictoriaLogs didn't manage to recover after %s, giving up", lc.config.FailMaxDuration)
		return false
	}

	return true
}

func (lc *VLClient) increaseTicker(ticker *time.Ticker) {
	maxTicker := 10 * time.Second
	if lc.currentTickerInterval < maxTicker {
		lc.currentTickerInterval *= 2
		if lc.currentTickerInterval > maxTicker {
			lc.currentTickerInterval = maxTicker
		}

		ticker.Reset(lc.currentTickerInterval)
	}
}

func (lc *VLClient) decreaseTicker(ticker *time.Ticker) {
	minTicker := 100 * time.Millisecond
	if lc.currentTickerInterval != minTicker {
		lc.currentTickerInterval = minTicker
		ticker.Reset(lc.currentTickerInterval)
	}
}

func (lc *VLClient) doQueryRange(ctx context.Context, uri string, c chan *Log, infinite bool) error {
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
			resp, err := lc.Get(ctx, uri)
			if err != nil {
				if ok := lc.shouldRetry(); !ok {
					return fmt.Errorf("querying range: %w", err)
				}

				lc.increaseTicker(ticker)

				continue
			}

			if resp.StatusCode != http.StatusOK {
				lc.Logger.Warnf("bad HTTP response code for query range: %d", resp.StatusCode)
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if ok := lc.shouldRetry(); !ok {
					return fmt.Errorf("bad HTTP response code: %d: %s: %w", resp.StatusCode, string(body), err)
				}

				lc.increaseTicker(ticker)

				continue
			}

			n, largestTime, err := lc.readResponse(ctx, resp, c)
			if err != nil {
				return fmt.Errorf("querying range: %w", err)
			}

			if !infinite && n < lc.config.Limit {
				lc.Logger.Infof("Got less than %d results (%d), stopping", lc.config.Limit, n)
				close(c)

				return nil
			}

			lc.Logger.Debugf("(timer:%v) %d results (uri:%s)", lc.currentTickerInterval, n, uri)

			if infinite {
				if n > 0 {
					// as long as we get results, we keep lowest ticker
					lc.decreaseTicker(ticker)
				} else {
					lc.increaseTicker(ticker)
				}
			}

			uri, err = updateURI(uri, largestTime)
			if err != nil {
				return fmt.Errorf("querying range: %w", err)
			}
		}
	}
}

// Parses response from body in JSON-LD format and sends results to the channel
func (lc *VLClient) readResponse(ctx context.Context, resp *http.Response, c chan *Log) (int, time.Time, error) {
	br := bufio.NewReaderSize(resp.Body, 64*1024)

	var (
		finishedReading bool
		n               int
		latestTS        time.Time
	)

	for !finishedReading {
		select {
		case <-ctx.Done():
			return n, latestTS, nil
		default:
		}

		b, err := br.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				lc.Logger.Infof("skipping line number #%d: line too long", n)
				continue
			}

			if errors.Is(err, io.EOF) {
				// b can be != nil when EOF is returned, so we need to process it
				finishedReading = true
			} else if errors.Is(err, context.Canceled) {
				return n, latestTS, nil
			} else {
				return n, latestTS, fmt.Errorf("cannot read line in response: %w", err)
			}
		}

		if len(b) == 0 {
			continue
		}

		b = bytes.Trim(b, "\n")

		var logLine Log

		if err := json.Unmarshal(b, &logLine); err != nil {
			lc.Logger.Warnf("cannot unmarshal line in response: %s", string(b))
			continue
		}

		n++

		lc.Logger.Tracef("Got response: %+v", logLine)
		c <- &logLine

		if logLine.Time.After(latestTS) {
			latestTS = logLine.Time
		}
	}

	return n, latestTS, nil
}

func (lc *VLClient) getURLFor(endpoint string, params map[string]string) string {
	u, err := url.Parse(lc.config.URL)
	if err != nil {
		return ""
	}

	queryParams := u.Query()

	for k, v := range params {
		queryParams.Set(k, v)
	}

	u.RawQuery = queryParams.Encode()

	u.Path, err = url.JoinPath(lc.config.Prefix, u.Path, endpoint)
	if err != nil {
		return ""
	}

	return u.String()
}

func (lc *VLClient) Ready(ctx context.Context) error {
	tick := time.NewTicker(500 * time.Millisecond)
	u := lc.getURLFor("", nil)

	for {
		select {
		case <-ctx.Done():
			tick.Stop()
			return ctx.Err()
		case <-lc.t.Dying():
			tick.Stop()
			return lc.t.Err()
		case <-tick.C:
			lc.Logger.Debug("Checking if VictoriaLogs is ready")

			resp, err := lc.Get(ctx, u)
			if err != nil {
				lc.Logger.Warnf("Error checking if VictoriaLogs is ready: %s", err)
				continue
			}

			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				lc.Logger.Debugf("VictoriaLogs is not ready, status code: %d", resp.StatusCode)
				continue
			}

			lc.Logger.Info("VictoriaLogs is ready")

			return nil
		}
	}
}

func (lc *VLClient) doTail(ctx context.Context, uri string, c chan *Log) error {

	// These control how the timing of requests when the active connection is lost
	minBackoff := 100 * time.Millisecond
	maxBackoff := 10 * time.Second
	backoffInterval := minBackoff
	queryStart := time.Now()

	for {
		// Wait for the backoff interval, respect context ending as well
		// Putting this first keeps the logic simpler
		if backoffInterval > maxBackoff {
			backoffInterval = maxBackoff
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-lc.t.Dying():
			return lc.t.Err()
		case <-time.After(backoffInterval):
			// now we can make the next request
		}

		// update start_offset in the request
		// This needs to be done just before the query is made, since
		// the desired offset depends on the query time.
		uri = updateTailURI(uri, queryStart)
		// Make the HTTP request
		resp, err := lc.Get(ctx, uri)
		if err != nil {
			lc.Logger.Warnf("error tailing logs: %w", err)
			backoffInterval *= 2
			continue
		}

		// Verify the HTTP response code
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lc.Logger.Warnf("bad HTTP response code for tail request: %d: %s: %w", resp.StatusCode, body, err)
			backoffInterval *= 2
			continue
		}

		// Read all the responses
		n, largestTime, err := lc.readResponse(ctx, resp, c)
		if err != nil {
			lc.Logger.Warnf("error while reading tail response: %w", err)
			backoffInterval *= 2
		} else if n > 0 {
			// as long as we get results, reset the backoff interval
			backoffInterval = minBackoff
			// update the queryStart time if the latest result was later
			if largestTime.After(queryStart) {
				queryStart = largestTime
			}
		} else {
			backoffInterval *= 2
		}

	}
}

// Tail live-tailing for logs
// See: https://docs.victoriametrics.com/victorialogs/querying/#live-tailing
func (lc *VLClient) Tail(ctx context.Context) (chan *Log, error) {
	t := time.Now().Add(-1 * lc.config.Since)
	u := lc.getURLFor("select/logsql/tail", map[string]string{
		"start_offset": "0",
		"query": lc.config.Query,
	})

	c := make(chan *Log)

	lc.Logger.Debugf("Since: %s (%s)", lc.config.Since, t)

	lc.Logger.Infof("Connecting to %s", u)
	lc.t.Go(func() error {
		return lc.doTail(ctx, u, c)
	})

	return c, nil
}

// QueryRange queries the logs
// See: https://docs.victoriametrics.com/victorialogs/querying/#querying-logs
func (lc *VLClient) QueryRange(ctx context.Context, infinite bool) chan *Log {
	t := time.Now().Add(-1 * lc.config.Since)
	u := lc.getURLFor("select/logsql/query", map[string]string{
		"query": lc.config.Query,
		"start": t.Format(time.RFC3339Nano),
		"limit": strconv.Itoa(lc.config.Limit),
	})

	c := make(chan *Log)

	lc.Logger.Debugf("Since: %s (%s)", lc.config.Since, t)

	lc.Logger.Infof("Connecting to %s", u)
	lc.t.Go(func() error {
		return lc.doQueryRange(ctx, u, c, infinite)
	})

	return c
}

func (lc *VLClient) Get(ctx context.Context, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	for k, v := range lc.requestHeaders {
		request.Header.Add(k, v)
	}

	lc.Logger.Debugf("GET %s", url)

	return lc.client.Do(request)
}

func NewVLClient(config Config) *VLClient {
	headers := make(map[string]string)
	maps.Copy(headers, config.Headers)

	if config.Username != "" || config.Password != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password))
	}

	headers["User-Agent"] = useragent.Default()

	return &VLClient{
		Logger:         log.WithField("component", "victorialogs-client"),
		config:         config,
		requestHeaders: headers,
		client:         &http.Client{},
	}
}
