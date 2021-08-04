package apiclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
)

var (
	InsecureSkipVerify = false
)

type ApiClient struct {
	/*The http client used to make requests*/
	client *http.Client
	/*Reuse a single struct instead of allocating one for each service on the heap.*/
	common service
	/*config stuff*/
	BaseURL   *url.URL
	URLPrefix string
	UserAgent string
	/*exposed Services*/
	Decisions *DecisionsService
	Alerts    *AlertsService
	Auth      *AuthService
	Metrics   *MetricsService
	Signal    *SignalService
}

type service struct {
	client *ApiClient
}

func NewClient(config *Config) (*ApiClient, error) {
	t := &JWTTransport{
		MachineID:      &config.MachineID,
		Password:       &config.Password,
		Scenarios:      config.Scenarios,
		URL:            config.URL,
		UserAgent:      config.UserAgent,
		VersionPrefix:  config.VersionPrefix,
		UpdateScenario: config.UpdateScenario,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: InsecureSkipVerify}
	c := &ApiClient{client: t.Client(), BaseURL: config.URL, UserAgent: config.UserAgent, URLPrefix: config.VersionPrefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)
	c.Metrics = (*MetricsService)(&c.common)
	c.Signal = (*SignalService)(&c.common)

	return c, nil
}

func NewDefaultClient(URL *url.URL, prefix string, userAgent string, client *http.Client) (*ApiClient, error) {
	if client == nil {
		client = &http.Client{}
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: InsecureSkipVerify}
	c := &ApiClient{client: client, BaseURL: URL, UserAgent: userAgent, URLPrefix: prefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)
	c.Metrics = (*MetricsService)(&c.common)
	c.Signal = (*SignalService)(&c.common)
	return c, nil
}

func RegisterClient(config *Config, client *http.Client) (*ApiClient, error) {
	if client == nil {
		client = &http.Client{}
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: InsecureSkipVerify}
	c := &ApiClient{client: client, BaseURL: config.URL, UserAgent: config.UserAgent, URLPrefix: config.VersionPrefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)

	resp, err := c.Auth.RegisterWatcher(context.Background(), models.WatcherRegistrationRequest{MachineID: &config.MachineID, Password: &config.Password})
	/*if we have http status, return it*/
	if err != nil {
		if resp != nil && resp.Response != nil {
			return nil, errors.Wrapf(err, "api register (%s) http %s : %s", c.BaseURL, resp.Response.Status, err)
		}
		return nil, errors.Wrapf(err, "api register (%s) : %s", c.BaseURL, err)
	}
	return c, nil

}

type Response struct {
	Response *http.Response
	//add our pagination stuff
	//NextPage int
	//...
}

type ErrorResponse struct {
	models.ErrorResponse
}

func (e *ErrorResponse) Error() string {
	err := fmt.Sprintf("API error: %s", *e.Message)
	if len(e.Errors) > 0 {
		err += fmt.Sprintf(" (%s)", e.Errors)
	}
	return err
}

func newResponse(r *http.Response) *Response {
	response := &Response{Response: r}
	return response
}

func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	errorResponse := &ErrorResponse{}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && data != nil {
		err := json.Unmarshal(data, errorResponse)
		if err != nil {
			return errors.Wrapf(err, "http code %d, invalid body", r.StatusCode)
		}
	} else {
		errorResponse.Message = new(string)
		*errorResponse.Message = fmt.Sprintf("http code %d, no error message", r.StatusCode)
	}
	return errorResponse
}

type ListOpts struct {
	//Page    int
	//PerPage int
}

type DeleteOpts struct {
	//??
}

type AddOpts struct {
	//??
}
