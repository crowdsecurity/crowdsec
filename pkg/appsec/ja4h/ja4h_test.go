package ja4h

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestJA4H_A(t *testing.T) {
	tests := []struct {
		name           string
		request        func() *http.Request
		expectedResult string
	}{
		{
			name: "basic GET request - HTTP1.1 - no accept-language header",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				return req
			},
			expectedResult: "ge11nn000000",
		},
		{
			name: "basic GET request - HTTP1.1 - with accept-language header",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.Header.Set("Accept-Language", "en-US")
				return req
			},
			expectedResult: "ge11nn01enus",
		},
		{
			name: "basic POST request - HTTP1.1 - no accept-language header - cookies - referer",
			request: func() *http.Request {
				req, _ := http.NewRequest("POST", "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				req.Header.Set("Referer", "http://example.com")
				return req
			},
			expectedResult: "po11cr000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jA4H_a(tt.request())
			if result != tt.expectedResult {
				t.Errorf("expected %s, got %s", tt.expectedResult, result)
			}
		})
	}
}

func TestJA4H_B(t *testing.T) {
	// This test is only for non-regression
	// Because go does not keep headers order, we just want to make sure our code always process the headers in the same order
	tests := []struct {
		name           string
		request        func() *http.Request
		expectedResult string
	}{
		{
			name: "no headers",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				return req
			},
			expectedResult: "e3b0c44298fc",
		},
		{
			name: "header with arbitrary content",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.Header.Set("X-Custom-Header", "some value")
				return req
			},
			expectedResult: "0a15aba5bbd6",
		},
		{
			name: "header with multiple headers",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.Header.Set("X-Custom-Header", "some value")
				req.Header.Set("Authorization", "Bearer token")
				return req
			},
			expectedResult: "bbfc6cf16ecb",
		},
		{
			name: "curl-like request",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://localhost", nil)
				req.Header.Set("Host", "localhost")
				req.Header.Set("User-Agent", "curl/8.12.1")
				req.Header.Set("Accept", "*/*")
				return req
			},
			expectedResult: "4722709a6f34",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jA4H_b(tt.request())
			if result != tt.expectedResult {
				t.Errorf("expected %s, got %s", tt.expectedResult, result)
			}
		})
	}
}

func TestJA4H_C(t *testing.T) {
	tests := []struct {
		name           string
		cookies        func() []*http.Cookie
		expectedResult string
	}{
		{
			name: "no cookies",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				return req.Cookies()
			},
			expectedResult: "000000000000",
		},
		{
			name: "one cookie",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				return req.Cookies()
			},
			expectedResult: "2c26b46b68ff",
		},
		{
			name: "duplicate cookies",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar2"})
				return req.Cookies()
			},
			expectedResult: "8990ce24137b",
		},
		{
			name: "multiple cookies",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				req.AddCookie(&http.Cookie{Name: "bar", Value: "foo"})
				cookies := req.Cookies()
				slices.SortFunc(cookies, func(a, b *http.Cookie) int {
					return strings.Compare(a.Name, b.Name)
				})
				return cookies
			},
			expectedResult: "41557db67d60",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jA4H_c(tt.cookies())
			if result != tt.expectedResult {
				t.Errorf("expected %s, got %s", tt.expectedResult, result)
			}
		})
	}
}

func TestJA4H_D(t *testing.T) {
	tests := []struct {
		name           string
		cookies        func() []*http.Cookie
		expectedResult string
	}{
		{
			name: "no cookies",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				return req.Cookies()
			},
			expectedResult: "000000000000",
		},
		{
			name: "one cookie",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				return req.Cookies()
			},
			expectedResult: "3ba8907e7a25",
		},
		{
			name: "duplicate cookies",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar2"})
				return req.Cookies()
			},
			expectedResult: "975821a3a881",
		},
		{
			name: "multiple cookies",
			cookies: func() []*http.Cookie {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				req.AddCookie(&http.Cookie{Name: "bar", Value: "foo"})
				cookies := req.Cookies()
				slices.SortFunc(cookies, func(a, b *http.Cookie) int {
					return strings.Compare(a.Name, b.Name)
				})
				return cookies
			},
			expectedResult: "70f8bee1efb8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jA4H_d(tt.cookies())
			if result != tt.expectedResult {
				t.Errorf("expected %s, got %s", tt.expectedResult, result)
			}
		})
	}
}

func TestJA4H(t *testing.T) {
	tests := []struct {
		name         string
		req          func() *http.Request
		expectedHash string
	}{
		{
			name: "Basic GET - No cookies",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				return req
			},
			expectedHash: "ge11nn000000_e3b0c44298fc_000000000000_000000000000",
		},
		{
			name: "Basic GET - With cookies",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "session", Value: "12345"})
				return req
			},
			expectedHash: "ge11cn000000_e3b0c44298fc_3f3af1ecebbd_86a3f0069fcd",
		},
		{
			name: "Basic GET - Multiple cookies",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
				req.AddCookie(&http.Cookie{Name: "baz", Value: "qux"})
				return req
			},
			expectedHash: "ge11cn000000_e3b0c44298fc_bd87575d11f6_d401f362552e",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash := JA4H(test.req())
			if hash != test.expectedHash {
				t.Errorf("expected %s, got %s", test.expectedHash, hash)
			}
		})
	}

}
