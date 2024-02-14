package cticlient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	CTIBaseUrl    = "https://cti.api.crowdsec.net/v2"
	smokeEndpoint = "/smoke"
	fireEndpoint  = "/fire"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrLimit        = errors.New("request quota exceeded, please reduce your request rate")
	ErrNotFound     = errors.New("ip not found")
	ErrDisabled     = errors.New("cti is disabled")
	ErrUnknown      = errors.New("unknown error")
)

type CrowdsecCTIClient struct {
	httpClient *http.Client
	apiKey     string
	Logger     *log.Entry
}

func (c *CrowdsecCTIClient) doRequest(method string, endpoint string, params map[string]string) ([]byte, error) {
	url := CTIBaseUrl + endpoint
	if len(params) > 0 {
		url += "?"
		for k, v := range params {
			url += fmt.Sprintf("%s=%s&", k, v)
		}
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return nil, ErrUnauthorized
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, ErrLimit
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("unexpected http code : %s", resp.Status)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return respBody, nil
}

func (c *CrowdsecCTIClient) GetIPInfo(ip string) (*SmokeItem, error) {
	body, err := c.doRequest(http.MethodGet, smokeEndpoint+"/"+ip, nil)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return &SmokeItem{}, nil
		}
		return nil, err
	}
	item := SmokeItem{}
	err = json.Unmarshal(body, &item)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (c *CrowdsecCTIClient) SearchIPs(ips []string) (*SearchIPResponse, error) {
	params := make(map[string]string)
	params["ips"] = strings.Join(ips, ",")
	body, err := c.doRequest(http.MethodGet, smokeEndpoint, params)
	if err != nil {
		return nil, err
	}
	searchIPResponse := SearchIPResponse{}
	err = json.Unmarshal(body, &searchIPResponse)
	if err != nil {
		return nil, err
	}
	return &searchIPResponse, nil
}

func (c *CrowdsecCTIClient) Fire(params FireParams) (*FireResponse, error) {
	paramsMap := make(map[string]string)
	if params.Page != nil {
		paramsMap["page"] = fmt.Sprintf("%d", *params.Page)
	}
	if params.Since != nil {
		paramsMap["since"] = *params.Since
	}
	if params.Limit != nil {
		paramsMap["limit"] = fmt.Sprintf("%d", *params.Limit)
	}

	body, err := c.doRequest(http.MethodGet, fireEndpoint, paramsMap)
	if err != nil {
		return nil, err
	}
	fireResponse := FireResponse{}
	err = json.Unmarshal(body, &fireResponse)
	if err != nil {
		return nil, err
	}
	return &fireResponse, nil
}

func NewCrowdsecCTIClient(options ...func(*CrowdsecCTIClient)) *CrowdsecCTIClient {
	client := &CrowdsecCTIClient{}
	for _, option := range options {
		option(client)
	}
	if client.httpClient == nil {
		client.httpClient = &http.Client{}
	}
	// we cannot return with a ni logger, so we set a default one
	if client.Logger == nil {
		client.Logger = log.NewEntry(log.New())
	}
	return client
}

func WithLogger(logger *log.Entry) func(*CrowdsecCTIClient) {
	return func(c *CrowdsecCTIClient) {
		c.Logger = logger
	}
}

func WithHTTPClient(httpClient *http.Client) func(*CrowdsecCTIClient) {
	return func(c *CrowdsecCTIClient) {
		c.httpClient = httpClient
	}
}

func WithAPIKey(apiKey string) func(*CrowdsecCTIClient) {
	return func(c *CrowdsecCTIClient) {
		c.apiKey = apiKey
	}
}
