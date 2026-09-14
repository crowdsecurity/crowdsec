package ja4h

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// newRequest builds a request with headers added in the given order (name/value
// pairs) and, when order is non-nil, the recorded wire order.
func newRequest(t *testing.T, ctx context.Context, headers, order []string) *http.Request {
	t.Helper()

	if order != nil {
		ctx = WithHeaderOrder(ctx, order)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)

	for i := 0; i < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}

	return req
}

// Expected hashes are the first 12 hex chars of the sha256 of the comma-joined
// header names, as the spec defines JA4H_b.
func TestJA4H_B_WireOrder(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name     string
		headers  []string // name/value pairs, in wire order
		order    []string // nil means no order was recorded
		expected string
	}{
		{
			name:     "wire order is preserved",
			headers:  []string{"Host", "example.com", "User-Agent", "curl/8", "Accept", "*/*"},
			order:    []string{"Host", "User-Agent", "Accept"},
			expected: "fe444ad14866", // Host,User-Agent,Accept
		},
		{
			name:     "same headers in another order hash differently",
			headers:  []string{"Host", "example.com", "User-Agent", "curl/8", "Accept", "*/*"},
			order:    []string{"Accept", "Host", "User-Agent"},
			expected: "4722709a6f34", // Accept,Host,User-Agent
		},
		{
			name:     "a repeated header is listed once per line",
			headers:  []string{"Accept", "text/html", "Accept", "*/*", "Host", "example.com"},
			order:    []string{"Accept", "Accept", "Host"},
			expected: "21baed29a28b", // Accept,Accept,Host
		},
		{
			name:     "cookie and referer are excluded from the order",
			headers:  []string{"Host", "example.com", "Cookie", "a=b", "User-Agent", "curl/8", "Referer", "http://x", "Accept", "*/*"},
			order:    []string{"Host", "Cookie", "User-Agent", "Referer", "Accept"},
			expected: "fe444ad14866", // Host,User-Agent,Accept
		},
		{
			name:     "names in the order but not in the map are dropped",
			headers:  []string{"Host", "example.com", "User-Agent", "curl/8", "Accept", "*/*"},
			order:    []string{"Host", "X-Crowdsec-Appsec-Ip", "User-Agent", "Accept"},
			expected: "fe444ad14866", // Host,User-Agent,Accept
		},
		{
			name:     "without a recorded order the names are sorted",
			headers:  []string{"Host", "example.com", "User-Agent", "curl/8", "Accept", "*/*"},
			order:    nil,
			expected: "4722709a6f34", // Accept,Host,User-Agent
		},
		{
			name:     "names missing from the order are appended sorted",
			headers:  []string{"Host", "example.com", "User-Agent", "curl/8", "Accept", "*/*"},
			order:    []string{"Host"},
			expected: "0d34275228c4", // Host,Accept,User-Agent
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, ctx, tc.headers, tc.order)
			require.Equal(t, tc.expected, jA4H_b(ja4hHeaders(req)))
		})
	}
}

// The reference implementation counts the header lines left after dropping
// cookies and referer, which is the same list JA4H_b hashes.
func TestJA4H_A_HeaderCount(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name     string
		headers  []string
		order    []string
		expected string
	}{
		{
			name:     "a repeated header counts once per line",
			headers:  []string{"Accept", "a", "Accept", "b", "Host", "x"},
			order:    []string{"Accept", "Accept", "Host"},
			expected: "03",
		},
		{
			name:     "cookie is excluded by prefix, not by exact name",
			headers:  []string{"Host", "x", "Cookie", "a=b", "Cookie2", "c=d", "Referer", "http://x", "Accept", "*/*"},
			order:    []string{"Host", "Cookie", "Cookie2", "Referer", "Accept"},
			expected: "02",
		},
		{
			name:     "without a recorded order a repeated header counts once",
			headers:  []string{"Accept", "a", "Accept", "b", "Host", "x"},
			order:    nil,
			expected: "02",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, ctx, tc.headers, tc.order)
			require.Equal(t, tc.expected, countHeaders(ja4hHeaders(req)))
		})
	}
}

func TestJA4H_A_HeaderCountCapped(t *testing.T) {
	headers := make([]string, 0, 2*120)
	order := make([]string, 0, 120)
	for i := range 120 {
		name := fmt.Sprintf("X-H-%d", i)
		headers = append(headers, name, "1")
		order = append(order, http.CanonicalHeaderKey(name))
	}

	req := newRequest(t, t.Context(), headers, order)
	require.Equal(t, "99", countHeaders(ja4hHeaders(req)))
}
