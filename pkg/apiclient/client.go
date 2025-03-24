package apiclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/golang-jwt/jwt/v4"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var (
	InsecureSkipVerify = false
	Cert               *tls.Certificate
	CaCertPool         *x509.CertPool
	lapiClient         *ApiClient
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
	Allowlists     *AllowlistsService
	Auth           *AuthService
	Metrics        *MetricsService
	Signal         *SignalService
	HeartBeat      *HeartBeatService
	UsageMetrics   *UsageMetricsService
}

func (a *ApiClient) GetClient() *http.Client {
	return a.client
}

func (a *ApiClient) IsEnrolled() bool {
	jwtTransport := a.client.Transport.(*JWTTransport)
	tokenStr := jwtTransport.Token

	token, _ := jwt.Parse(tokenStr, nil)
	if token == nil {
		return false
	}

	claims := token.Claims.(jwt.MapClaims)
	_, ok := claims["organization_id"]

	return ok
}

type service struct {
	client *ApiClient
}

func InitLAPIClient(ctx context.Context, apiUrl string, papiUrl string, login string, password string, scenarios []string) error {
	apiURL, err := url.Parse(apiUrl)
	if err != nil {
		return fmt.Errorf("parsing api url ('%s'): %w", apiURL, err)
	}

	papiURL, err := url.Parse(papiUrl)
	if err != nil {
		return fmt.Errorf("parsing polling api url ('%s'): %w", papiURL, err)
	}

	pwd := strfmt.Password(password)

	client, err := NewClient(&Config{
		MachineID:     login,
		Password:      pwd,
		Scenarios:     scenarios,
		URL:           apiURL,
		PapiURL:       papiURL,
		VersionPrefix: "v1",
		UpdateScenario: func(_ context.Context) ([]string, error) {
			return scenarios, nil
		},
	})
	if err != nil {
		return fmt.Errorf("new client api: %w", err)
	}

	authResp, _, err := client.Auth.AuthenticateWatcher(ctx, models.WatcherAuthRequest{
		MachineID: &login,
		Password:  &pwd,
		Scenarios: scenarios,
	})
	if err != nil {
		return fmt.Errorf("authenticate watcher (%s): %w", login, err)
	}

	var expiration time.Time
	if err := expiration.UnmarshalText([]byte(authResp.Expire)); err != nil {
		return fmt.Errorf("unable to parse jwt expiration: %w", err)
	}

	client.GetClient().Transport.(*JWTTransport).Token = authResp.Token
	client.GetClient().Transport.(*JWTTransport).Expiration = expiration

	lapiClient = client

	return nil
}

func GetLAPIClient() (*ApiClient, error) {
	if lapiClient == nil {
		return nil, errors.New("client not initialized")
	}

	return lapiClient, nil
}

func NewClient(config *Config) (*ApiClient, error) {
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = useragent.Default()
	}

	t := &JWTTransport{
		MachineID:      &config.MachineID,
		Password:       &config.Password,
		Scenarios:      config.Scenarios,
		UserAgent:      userAgent,
		VersionPrefix:  config.VersionPrefix,
		UpdateScenario: config.UpdateScenario,
		RetryConfig: NewRetryConfig(
			WithStatusCodeConfig(http.StatusUnauthorized, 2, false, true),
			WithStatusCodeConfig(http.StatusForbidden, 2, false, true),
			WithStatusCodeConfig(http.StatusTooManyRequests, 5, true, false),
			WithStatusCodeConfig(http.StatusServiceUnavailable, 5, true, false),
			WithStatusCodeConfig(http.StatusGatewayTimeout, 5, true, false),
		),
	}

	transport, baseURL := createTransport(config.URL)
	if transport != nil {
		t.Transport = transport
	} else {
		// can be httpmock.MockTransport
		if ht, ok := http.DefaultTransport.(*http.Transport); ok {
			t.Transport = ht.Clone()
		}
	}

	t.URL = baseURL

	tlsconfig := tls.Config{InsecureSkipVerify: InsecureSkipVerify}
	tlsconfig.RootCAs = CaCertPool

	if Cert != nil {
		tlsconfig.Certificates = []tls.Certificate{*Cert}
	}

	if t.Transport != nil {
		t.Transport.(*http.Transport).TLSClientConfig = &tlsconfig
	}

	c := &ApiClient{client: t.Client(), BaseURL: baseURL, UserAgent: userAgent, URLPrefix: config.VersionPrefix, PapiURL: config.PapiURL}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Allowlists = (*AllowlistsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)
	c.Metrics = (*MetricsService)(&c.common)
	c.Signal = (*SignalService)(&c.common)
	c.DecisionDelete = (*DecisionDeleteService)(&c.common)
	c.HeartBeat = (*HeartBeatService)(&c.common)
	c.UsageMetrics = (*UsageMetricsService)(&c.common)

	return c, nil
}

func NewDefaultClient(url *url.URL, prefix string, userAgent string, client *http.Client) (*ApiClient, error) {
	transport, baseURL := createTransport(url)

	if client == nil {
		client = &http.Client{}

		if transport != nil {
			client.Transport = transport
		} else {
			if ht, ok := http.DefaultTransport.(*http.Transport); ok {
				ht = ht.Clone()
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

	if userAgent == "" {
		userAgent = useragent.Default()
	}

	c := &ApiClient{client: client, BaseURL: baseURL, UserAgent: userAgent, URLPrefix: prefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Allowlists = (*AllowlistsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)
	c.Metrics = (*MetricsService)(&c.common)
	c.Signal = (*SignalService)(&c.common)
	c.DecisionDelete = (*DecisionDeleteService)(&c.common)
	c.HeartBeat = (*HeartBeatService)(&c.common)
	c.UsageMetrics = (*UsageMetricsService)(&c.common)

	return c, nil
}

func RegisterClient(ctx context.Context, config *Config, client *http.Client) (*ApiClient, error) {
	transport, baseURL := createTransport(config.URL)

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

			client.Transport = http.DefaultTransport.(*http.Transport).Clone()
			client.Transport.(*http.Transport).TLSClientConfig = &tlsconfig
		}
	} else if client.Transport == nil && transport != nil {
		client.Transport = transport
	}

	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = useragent.Default()
	}

	c := &ApiClient{client: client, BaseURL: baseURL, UserAgent: userAgent, URLPrefix: config.VersionPrefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)

	resp, err := c.Auth.RegisterWatcher(ctx, models.WatcherRegistrationRequest{MachineID: &config.MachineID, Password: &config.Password, RegistrationToken: config.RegistrationToken})
	if err != nil {
		/*if we have http status, return it*/
		if resp != nil && resp.Response != nil {
			return nil, fmt.Errorf("api register (%s) http %s: %w", c.BaseURL, resp.Response.Status, err)
		}

		return nil, fmt.Errorf("api register (%s): %w", c.BaseURL, err)
	}

	return c, nil
}

func createTransport(url *url.URL) (*http.Transport, *url.URL) {
	urlString := url.String()

	// TCP transport
	if !strings.HasPrefix(urlString, "/") {
		return nil, url
	}

	// Unix transport
	url.Path = "/"
	url.Host = "unix"
	url.Scheme = "http"

	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", strings.TrimSuffix(urlString, "/"))
		},
	}, url
}

type Response struct {
	Response *http.Response
	// add our pagination stuff
	// NextPage int
	// ...
}

func newResponse(r *http.Response) *Response {
	return &Response{Response: r}
}

type ListOpts struct {
	// Page    int
	// PerPage int
}

type DeleteOpts struct {
	// ??
}

type AddOpts struct {
	// ??
}
