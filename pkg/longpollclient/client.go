package longpollclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type LongPollClient struct {
	t          tomb.Tomb
	c          chan *Event
	url        url.URL
	logger     *log.Entry
	since      int64
	httpClient *http.Client
	lastId     uuid.UUID
}

type LongPollClientConfig struct {
	Url        url.URL
	Logger     *log.Logger
	HttpClient *http.Client
}

type Event struct {
	Timestamp int64     `json:"timestamp"`
	Category  string    `json:"category"`
	Data      string    `json:"data"`
	ID        uuid.UUID `json:"id"`
}

type pollResponse struct {
	Events []*Event `json:"events"`
	// Set for timeout responses
	Timestamp int64 `json:"timestamp"`
	// API error responses could have an informative error here. Empty on success.
	ErrorMessage string `json:"error"`
}

func (c *LongPollClient) doQuery() error {

	logger := c.logger.WithField("method", "doQuery")

	query := c.url.Query()
	query.Set("since_time", fmt.Sprintf("%d", c.since))
	query.Set("last_id", c.lastId.String())
	query.Set("timeout", "45")
	c.url.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", c.url.String(), nil)
	if err != nil {
		logger.Errorf("failed to create request: %s", err)
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Errorf("failed to execute request: %s", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.logger.Errorf("unexpected status code: %d", resp.StatusCode)
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)

	for {
		select {
		case <-c.t.Dying():
			logger.Debugf("dying")
			close(c.c)
			return nil
		default:
			var pollResp pollResponse
			err = decoder.Decode(&pollResp)
			if err != nil {
				if err == io.EOF {
					logger.Debugf("server closed connection")
					return nil
				}
				return fmt.Errorf("error decoding poll response: %v", err)
			}

			logger.Tracef("got response: %+v", pollResp)

			if len(pollResp.ErrorMessage) > 0 {
				return fmt.Errorf("longpoll API error message: %s", pollResp.ErrorMessage)
			}

			if len(pollResp.Events) > 0 {
				c.logger.Debugf("got %d events", len(pollResp.Events))
				for _, event := range pollResp.Events {
					c.c <- event
					if event.Timestamp > c.since {
						c.since = event.Timestamp
						c.lastId = event.ID
					}
				}
			}
			if pollResp.Timestamp > 0 {
				c.since = pollResp.Timestamp
			}
		}
	}
}

func (c *LongPollClient) pollEvents() error {
	for {
		select {
		case <-c.t.Dying():
			c.logger.Debug("dying")
			return nil
		default:
			c.logger.Info("Polling PAPI")
			err := c.doQuery()
			if err != nil {
				c.logger.Errorf("failed to poll: %s", err)
				continue
			}
		}
	}
}

func (c *LongPollClient) Start(since time.Time) chan *Event {
	c.logger.Infof("starting polling client")
	c.c = make(chan *Event)
	c.since = since.Unix() * 1000
	c.t.Go(c.pollEvents)
	return c.c
}

func (c *LongPollClient) Stop() error {
	c.t.Kill(nil)
	return nil
}

func NewLongPollClient(config LongPollClientConfig) (*LongPollClient, error) {
	var logger *log.Entry
	if config.Url == (url.URL{}) {
		return nil, fmt.Errorf("url is required")
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
