package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (c *ApiClient) NewRequest(method, url string, body interface{}) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}
	u, err := c.BaseURL.Parse(url)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if body != nil {
		buf = &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		err := enc.Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func (c *ApiClient) Do(ctx context.Context, req *http.Request, v interface{}) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("context must be non-nil")
	}
	req = req.WithContext(ctx)

	// Check rate limit

	if c.UserAgent != "" {
		req.Header.Add("User-Agent", c.UserAgent)
	}

	if log.GetLevel() >= log.DebugLevel {
		log.Debugf("[URL] %s %s", req.Method, req.URL)
	}
	resp, err := c.client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		// If we got an error, and the context has been canceled,
		// the context's error is probably more useful.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// If the error type is *url.Error, sanitize its URL before returning.
		if e, ok := err.(*url.Error); ok {
			if url, err := url.Parse(e.URL); err == nil {
				e.URL = url.String()
				return newResponse(resp), e
			}
			return newResponse(resp), err
		}
		return newResponse(resp), err
	}

	if log.GetLevel() >= log.DebugLevel {
		for k, v := range resp.Header {
			log.Debugf("[headers] %s : %s", k, v)
		}

		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			log.Debugf("Response: %s", string(dump))
		}
	}

	response := newResponse(resp)

	err = CheckResponse(resp)
	if err != nil {
		return response, err
	}

	if v != nil {
		w, ok := v.(io.Writer)
		if !ok {
			decErr := json.NewDecoder(resp.Body).Decode(v)
			if errors.Is(decErr, io.EOF) {
				decErr = nil // ignore EOF errors caused by empty response body
			}
			return response, decErr
		}
		io.Copy(w, resp.Body)
	}
	return response, err
}
