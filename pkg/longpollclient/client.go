package longpollclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/logging"
)

type LongPollClient struct {
	mu         sync.Mutex
	cancelPoll context.CancelFunc
	done       chan struct{}
	c          chan Event
	url        url.URL
	logger     *log.Entry
	since      int64
	timeout    string
	httpClient *http.Client
}

type LongPollClientConfig struct {
	Url        url.URL
	Logger     logging.ExtLogger
	HttpClient *http.Client
}

type Event struct {
	Timestamp int64     `json:"timestamp"`
	Category  string    `json:"category"`
	Data      string    `json:"data"`
	ID        uuid.UUID `json:"id"`
	RequestId string
}

type pollResponse struct {
	Events []Event `json:"events"`
	// Set for timeout responses
	Timestamp int64 `json:"timestamp"`
	// API error responses could have an informative error here. Empty on success.
	ErrorMessage string `json:"error"`
}

var errUnauthorized = errors.New("user is not authorized to use PAPI")

const timeoutMessage = "no events before timeout"

func (c *LongPollClient) doQuery(ctx context.Context) (*http.Response, error) {
	logger := c.logger.WithField("method", "doQuery")
	query := c.url.Query()
	query.Set("since_time", fmt.Sprintf("%d", c.since))
	query.Set("timeout", c.timeout)
	c.url.RawQuery = query.Encode()

	logger.Debugf("Query parameters: %s", c.url.RawQuery)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url.String(), http.NoBody)
	if err != nil {
		logger.Errorf("failed to create request: %s", err)
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, ctx.Err() // Don't log
		}
		logger.Errorf("failed to execute request: %s", err)
		return nil, err
	}
	return resp, nil
}

func (c *LongPollClient) poll(ctx context.Context) error {
	logger := c.logger.WithField("method", "poll")

	resp, err := c.doQuery(ctx)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	requestID := resp.Header.Get("X-Amzn-Trace-Id")
	logger = logger.WithField("request-id", requestID)
	if resp.StatusCode != http.StatusOK {
		c.logger.Errorf("unexpected status code: %d", resp.StatusCode)
		if resp.StatusCode == http.StatusPaymentRequired {
			bodyContent, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.Errorf("failed to read response body: %s", err)
				return err
			}
			logger.Error(string(bodyContent))
			return errUnauthorized
		}
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)

	for {
		select {
		case <-ctx.Done():
			logger.Debug("context canceled")
			return ctx.Err()
		default:
			var pollResp pollResponse
			err = decoder.Decode(&pollResp)
			if err != nil {
				if errors.Is(err, io.EOF) {
					logger.Debug("server closed connection")
					return nil
				}
				return fmt.Errorf("error decoding poll response: %v", err)
			}

			logger.Tracef("got response: %+v", pollResp)

			if pollResp.ErrorMessage != "" {
				if pollResp.ErrorMessage == timeoutMessage {
					logger.Debug("got timeout message")
					return nil
				}
				return fmt.Errorf("longpoll API error message: %s", pollResp.ErrorMessage)
			}

			if len(pollResp.Events) > 0 {
				logger.Debugf("got %d events", len(pollResp.Events))
				for _, event := range pollResp.Events {
					event.RequestId = requestID
					select {
					case <-ctx.Done():
						return ctx.Err()
					case c.c <- event:
					}
					if event.Timestamp > c.since {
						c.since = event.Timestamp
					}
				}
			}
			if pollResp.Timestamp > 0 {
				c.since = pollResp.Timestamp
			}
			logger.Debugf("Since is now %d", c.since)
		}
	}
}

func (c *LongPollClient) pollEvents(ctx context.Context) error {
	initialBackoff := 1 * time.Second
	maxBackoff := 30 * time.Second
	currentBackoff := initialBackoff

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("context canceled")
			return nil
		default:
			c.logger.Debug("Polling PAPI")
			err := c.poll(ctx)
			if err != nil {
				if errors.Is(err, errUnauthorized) {
					c.logger.Errorf("unauthorized, stopping polling")
					return err
				}
				if errors.Is(err, context.Canceled) {
					c.logger.Debug("context canceled, stopping polling")
					return nil
				}
				c.logger.Errorf("failed to poll: %s, retrying in %s", err, currentBackoff)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(currentBackoff):
				}

				currentBackoff *= 2
				if currentBackoff > maxBackoff {
					currentBackoff = maxBackoff
				}
				continue
			}
			currentBackoff = initialBackoff
		}
	}
}

func (c *LongPollClient) Start(ctx context.Context, since time.Time) chan Event {
	_ = c.Stop()

	c.logger.Info("starting polling client")

	pollCtx, cancel := context.WithCancel(ctx)
	out := make(chan Event)
	done := make(chan struct{})

	c.mu.Lock()
	c.c = out
	c.since = since.Unix() * 1000
	c.timeout = "45"
	c.cancelPoll = cancel
	c.done = done
	c.mu.Unlock()

	go func() {
		defer close(done)
		defer close(out)
		_ = c.pollEvents(pollCtx)
	}()

	return out
}

func (c *LongPollClient) Stop() error {
	c.mu.Lock()
	cancel := c.cancelPoll
	done := c.done
	c.cancelPoll = nil
	c.done = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	if done != nil {
		<-done
	}

	return nil
}

func (c *LongPollClient) PullOnce(ctx context.Context, since time.Time) ([]Event, error) {
	c.logger.Debug("Pulling PAPI once")
	c.since = since.Unix() * 1000
	c.timeout = "1"
	resp, err := c.doQuery(ctx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	evts := []Event{}
	for {
		var pollResp pollResponse
		err = decoder.Decode(&pollResp)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.logger.Debug("server closed connection")
				break
			}
			log.Errorf("error decoding poll response: %v", err)
			break
		}

		c.logger.Tracef("got response: %+v", pollResp)

		if pollResp.ErrorMessage != "" {
			if pollResp.ErrorMessage == timeoutMessage {
				c.logger.Debug("got timeout message")
				break
			}
			log.Errorf("longpoll API error message: %s", pollResp.ErrorMessage)
			break
		}
		evts = append(evts, pollResp.Events...)
	}
	return evts, nil
}

func NewLongPollClient(config LongPollClientConfig) (*LongPollClient, error) {
	var logger *log.Entry
	if config.Url == (url.URL{}) {
		return nil, errors.New("url is required")
	}
	if config.Logger == nil {
		logger = log.WithField("component", "longpollclient")
	} else {
		logger = config.Logger.WithFields(log.Fields{
			"component": "longpollclient",
			"url":       config.Url.String(),
		})
	}

	return &LongPollClient{
		url:        config.Url,
		logger:     logger,
		httpClient: config.HttpClient,
	}, nil
}
