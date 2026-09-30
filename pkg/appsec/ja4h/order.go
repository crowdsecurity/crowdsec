package ja4h

import (
	"context"
	"net/http"
	"slices"
)

type headerOrderKey struct{}

// WithHeaderOrder records the header names in wire order, which http.Header
// loses and JA4H_b needs. Only the parsing server knows it.
func WithHeaderOrder(ctx context.Context, order []string) context.Context {
	return context.WithValue(ctx, headerOrderKey{}, order)
}

// HeaderOrder returns the wire order recorded by WithHeaderOrder, or nil.
func HeaderOrder(ctx context.Context) []string {
	order, _ := ctx.Value(headerOrderKey{}).([]string)
	return order
}

// orderedHeaderNames lists req.Header names in wire order, once per line. Names
// missing from the recorded order (or all of them, with net/http) are appended
// sorted so the fingerprint stays stable.
func orderedHeaderNames(req *http.Request) []string {
	names := make([]string, 0, len(req.Header))
	seen := make(map[string]bool, len(req.Header))

	for _, name := range HeaderOrder(req.Context()) {
		if _, ok := req.Header[name]; !ok {
			continue // dropped after parsing, e.g. the X-Crowdsec-Appsec-* metadata
		}
		seen[name] = true
		names = append(names, name)
	}

	rest := make([]string, 0, len(req.Header))
	for name := range req.Header {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	slices.Sort(rest)

	return append(names, rest...)
}
