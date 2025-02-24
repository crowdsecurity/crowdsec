package exprhelpers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJA4H(t *testing.T) {

	tests := []struct {
		name         string
		method       string
		url          string
		cookies      map[string]string
		headers      map[string]string
		expectedHash string
	}{
		{
			name:         "Basic GET - No cookies",
			method:       "GET",
			url:          "http://example.com",
			cookies:      map[string]string{},
			headers:      map[string]string{},
			expectedHash: "ge11nn000000_e3b0c44298fc_000000000000_000000000000",
		},
		{
			name:         "Basic POST - No cookies",
			method:       "POST",
			url:          "http://example.com",
			cookies:      map[string]string{},
			headers:      map[string]string{},
			expectedHash: "po11nn000000_e3b0c44298fc_000000000000_000000000000",
		},
		{
			name:   "GET - With cookies",
			method: "GET",
			url:    "http://example.com/foobar",
			cookies: map[string]string{
				"foo": "bar",
				"baz": "qux",
			},
			headers: map[string]string{
				"User-Agent": "Mozilla/5.0",
			},
			expectedHash: "ge11cn010000_b8bcd45ac095_bd87575d11f6_d401f362552e",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(test.method, test.url, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %s", err)
			}

			for key, value := range test.cookies {
				req.AddCookie(&http.Cookie{
					Name:  key,
					Value: value,
				})
			}

			for key, value := range test.headers {
				req.Header.Add(key, value)
			}

			hash, err := JA4H(req)
			require.NoError(t, err)

			if hash != test.expectedHash {
				t.Fatalf("JA4H returned unexpected hash: %s", hash)
			}
		})
	}

}
