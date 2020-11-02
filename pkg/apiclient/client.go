package apiclient

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

var BaseURL *url.URL
var URLPrefix = "v1"
var UserAgent string
var (
	InsecureSkipVerify = true
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
}

type service struct {
	client *ApiClient
}

func NewClient(httpClient *http.Client) *ApiClient {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: InsecureSkipVerify}
	c := &ApiClient{client: httpClient, BaseURL: BaseURL, UserAgent: UserAgent, URLPrefix: URLPrefix}
	c.common.client = c
	c.Decisions = (*DecisionsService)(&c.common)
	c.Alerts = (*AlertsService)(&c.common)
	c.Auth = (*AuthService)(&c.common)
	return c
}

type Response struct {
	Response *http.Response
	//add our pagination stuff
	//NextPage int
	//...
}

type ErrorResponse struct {
	Response *http.Response // HTTP response that caused this error
	Message  string         `json:"message"` // error message
	Errors   []string       `json:"errors"`  // more detail on individual errors
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("API error (%s) : %+v", e.Message, e.Errors)
}

func newResponse(r *http.Response) *Response {
	response := &Response{Response: r}
	//response.populatePageValues()
	return response
}

func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	errorResponse := &ErrorResponse{Response: r}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && data != nil {
		json.Unmarshal(data, errorResponse)
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
