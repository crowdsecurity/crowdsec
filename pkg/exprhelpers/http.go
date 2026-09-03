package exprhelpers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient/useragent"
)

const (
	exprHTTPTimeout     = 10 * time.Second
	exprHTTPMaxBodySize = 10 << 20 // 10 MiB cap to avoid OOM on huge responses
)

type HTTPResponse struct {
	StatusCode int
	Body       string
	Headers    http.Header
}

type httpHelperTransport struct {
	next http.RoundTripper
}

func (t *httpHelperTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", useragent.Default())
	}

	return t.next.RoundTrip(req)
}

var exprHTTPClient = &http.Client{
	Timeout:   exprHTTPTimeout,
	Transport: &httpHelperTransport{next: http.DefaultTransport},
}

func doHTTPRequest(method, uri string, headers map[string]string, body io.Reader) (*HTTPResponse, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, uri, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := exprHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, exprHTTPMaxBodySize))
	if err != nil {
		return nil, err
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       string(b),
		Headers:    resp.Header,
	}, nil
}

// HTTPGet(url string) (*HTTPResponse, error)
func HTTPGet(params ...any) (any, error) {
	uri, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for url: %T", params[0])
	}

	return doHTTPRequest(http.MethodGet, uri, nil, nil)
}

// HTTPHead(url string) (*HTTPResponse, error)
func HTTPHead(params ...any) (any, error) {
	uri, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for url: %T", params[0])
	}

	return doHTTPRequest(http.MethodHead, uri, nil, nil)
}

// HTTPPost(url string, contentType string, body string) (*HTTPResponse, error)
func HTTPPost(params ...any) (any, error) {
	uri, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for url: %T", params[0])
	}

	contentType, ok := params[1].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for contentType: %T", params[1])
	}

	body, ok := params[2].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for body: %T", params[2])
	}

	headers := map[string]string{"Content-Type": contentType}

	return doHTTPRequest(http.MethodPost, uri, headers, strings.NewReader(body))
}

// HTTPRequest(method string, url string, headers map[string]any, body string) (*HTTPResponse, error)
func HTTPRequest(params ...any) (any, error) {
	method, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for method: %T", params[0])
	}

	uri, ok := params[1].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for url: %T", params[1])
	}

	// headers is map[string]any so that expr map literals (map[string]interface{})
	// are accepted; values are stringified.
	rawHeaders, ok := params[2].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid type for headers: %T", params[2])
	}

	headers := make(map[string]string, len(rawHeaders))
	for k, v := range rawHeaders {
		headers[k] = fmt.Sprint(v)
	}

	body, ok := params[3].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for body: %T", params[3])
	}

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	return doHTTPRequest(method, uri, headers, reader)
}
