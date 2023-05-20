package apiclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	InsecureSkipVerify = false
	Cert               *tls.Certificate
	CaCertPool         *x509.CertPool
)

type ApiClient struct {
	/*The http client used to make requests*/
	client *http.Client
	/*Reuse a single struct instead of allocating one for each service on the heap.*/
	common service
	/*config stuff*/
	BaseURL   *url.URL
	PapiURL   *url.URL
	URLPrefix string
	UserAgent string
	/*exposed Services*/
	Decisions      *DecisionsService
	DecisionDelete *DecisionDeleteService
	Alerts         *AlertsService
	Auth           *AuthService
	Metrics        *MetricsService
	Signal         *SignalService
	HeartBeat      *HeartBeatService
}

func (a *ApiClient) GetClient() *http.Client {
	return a.client
}

type service struct {
	client *ApiClient
}

func NewClient(config *Config) (*ApiClient, error) {
	t := &JWTTransport{
		MachineID:      &config.MachineID,
		Password:       &config.Password,
		Scenarios:      config.Scenarios,
		UserAgent:      config.UserAgent,
		VersionPrefix:  config.VersionPrefix,
		UpdateScenario: config.UpdateScenario,
	}
	transport, baseUrl := CreateTransport(config.URL)
	if transport != nil {
		t.Transport = transport
	}
	t.URL = baseUrl

	tlsconfig := tls.Config{InsecureSkipVerify: InsecureSkipVerify}
	tlsconfig.RootCAs = CaCertPool
	if Cert != nil {
		tlsconfig.Certificates = []tls.Certificate{*Cert}
	}
	if ht, ok := http.DefaultTransport.(*http.Transport); ok {
		ht.TLSClientConfig = &tlsconfig
	}
	c := &ApiClient{client: t.Client(), BaseURL: baseUrl, UserAgent: config.UserAgent, URLPrefix: config.VersionPrefix, PapiURL: config.PapiURL}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)
	c.Metrics = (*MetricsService)(&c.common)
	c.Signal = (*SignalService)(&c.common)
	c.DecisionDelete = (*DecisionDeleteService)(&c.common)
	c.HeartBeat = (*HeartBeatService)(&c.common)

	return c, nil
}

func NewDefaultClient(URL *url.URL, prefix string, userAgent string, client *http.Client) (*ApiClient, error) {
	transport, baseUrl := CreateTransport(URL)
	if client == nil {
		client = &http.Client{}
		if transport != nil {
			client.Transport = transport
		} else {
			if ht, ok := http.DefaultTransport.(*http.Transport); ok {
				tlsconfig := tls.Config{InsecureSkipVerify: InsecureSkipVerify}
				tlsconfig.RootCAs = CaCertPool
				if Cert != nil {
					tlsconfig.Certificates = []tls.Certificate{*Cert}
				}
				ht.TLSClientConfig = &tlsconfig
				client.Transport = ht
			}
		}
	}
	c := &ApiClient{client: client, BaseURL: baseUrl, UserAgent: userAgent, URLPrefix: prefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)
	c.Metrics = (*MetricsService)(&c.common)
	c.Signal = (*SignalService)(&c.common)
	c.DecisionDelete = (*DecisionDeleteService)(&c.common)
	c.HeartBeat = (*HeartBeatService)(&c.common)

	return c, nil
}

func RegisterClient(config *Config, client *http.Client) (*ApiClient, error) {
	transport, baseUrl := CreateTransport(config.URL)
	if client == nil {
		client = &http.Client{}
		if transport != nil {
			client.Transport = transport
		} else {
			tlsconfig := tls.Config{InsecureSkipVerify: InsecureSkipVerify}
			if Cert != nil {
				tlsconfig.RootCAs = CaCertPool
				tlsconfig.Certificates = []tls.Certificate{*Cert}
			}
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsconfig
		}
	} else if client.Transport == nil && transport != nil {
		client.Transport = transport
	}

	c := &ApiClient{client: client, BaseURL: baseUrl, UserAgent: config.UserAgent, URLPrefix: config.VersionPrefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)

	resp, err := c.Auth.RegisterWatcher(context.Background(), models.WatcherRegistrationRequest{MachineID: &config.MachineID, Password: &config.Password})
	/*if we have http status, return it*/
	if err != nil {
		if resp != nil && resp.Response != nil {
			return nil, fmt.Errorf("api register (%s) http %s: %w", c.BaseURL, resp.Response.Status, err)
		}
		return nil, fmt.Errorf("api register (%s): %w", c.BaseURL, err)
	}
	return c, nil

}

func CreateTransport(url *url.URL) (*http.Transport, *url.URL) {
	urlString := url.String()
	if strings.HasPrefix(urlString, "/") {
		ToUnixSocketUrl(url)
		return &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", strings.TrimSuffix(urlString, "/"))
			},
		}, url
	} else {
		return nil, url
	}
}

func ToUnixSocketUrl(url *url.URL) {
	url.Path = "/"
	url.Host = "unix"
	url.Scheme = "http"
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
	if c := r.StatusCode; 200 <= c && c <= 299 || c == 304 {
		return nil
	}
	errorResponse := &ErrorResponse{}
	data, err := io.ReadAll(r.Body)
	if err == nil && data != nil {
		err := json.Unmarshal(data, errorResponse)
		if err != nil {
			return fmt.Errorf("http code %d, invalid body: %w", r.StatusCode, err)
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
