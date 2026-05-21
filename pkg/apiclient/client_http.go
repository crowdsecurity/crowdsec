package apiclient

import (
	"bytes"
	"compress/gzip"
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

const compressionMinSize = 5 * 1024 // 5KB

func (c *ApiClient) PrepareRequest(ctx context.Context, method, url string, body any) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}

	u, err := c.BaseURL.Parse(url)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	compressedBody := false

	if body != nil {
		jsonBuf := &bytes.Buffer{}
		enc := json.NewEncoder(jsonBuf)
		enc.SetEscapeHTML(false)

		if err = enc.Encode(body); err != nil {
			return nil, err
		}

		jsonBytes := jsonBuf.Bytes()
		if len(jsonBytes) > compressionMinSize {
			compressedBody = true
			buf = &bytes.Buffer{}
			gzipWriter := gzip.NewWriter(buf)
			if _, err = gzipWriter.Write(jsonBytes); err != nil {
				return nil, fmt.Errorf("writing to gzip writer: %w", err)
			}
			if err = gzipWriter.Close(); err != nil {
				return nil, fmt.Errorf("closing gzip writer: %w", err)
			}
		} else {
			buf = jsonBuf
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if compressedBody {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}

	return req, nil
}

func (c *ApiClient) Do(ctx context.Context, req *http.Request, v any) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("context must be non-nil")
	}

	req = req.WithContext(ctx)

	// Check rate limit

	if c.UserAgent != "" {
		req.Header.Add("User-Agent", c.UserAgent)
	}

	log.Debugf("[URL] %s %s", req.Method, req.URL)

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
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			if parsedURL, parseErr := url.Parse(urlErr.URL); parseErr == nil {
				urlErr.URL = parsedURL.String()
				return newResponse(resp), urlErr
			}

			return newResponse(resp), err
		}

		return newResponse(resp), err
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		for k, v := range resp.Header {
			log.Tracef("[headers] %s: %s", k, v)
		}

		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			log.Tracef("Response: %s", string(dump))
		}
	}

	response := newResponse(resp)

	err = CheckResponse(resp)
	if err != nil {
		return response, err
	}

	if v != nil {
		if w, ok := v.(io.Writer); ok {
			_, copyErr := io.Copy(w, resp.Body)
			return response, copyErr
		}

		decErr := json.NewDecoder(resp.Body).Decode(v)
		if errors.Is(decErr, io.EOF) {
			decErr = nil // ignore EOF errors caused by empty response body
		}

		return response, decErr
	}

	return response, err
}
