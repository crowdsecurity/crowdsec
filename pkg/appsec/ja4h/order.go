package ja4h

import (
	"context"
	"net/http"
	"slices"
)

type headerOrderKey struct{}

// WithHeaderOrder carries the header names in the order their lines appeared on
// the wire. JA4H_b hashes them in that order and an http.Header map cannot keep
// it, so the HTTP server has to record it while parsing.
func WithHeaderOrder(ctx context.Context, order []string) context.Context {
	return context.WithValue(ctx, headerOrderKey{}, order)
}

// HeaderOrder returns the wire order recorded by WithHeaderOrder, or nil.
func HeaderOrder(ctx context.Context) []string {
	order, _ := ctx.Value(headerOrderKey{}).([]string)
	return order
}

// orderedHeaderNames lists the names of req.Header as they appeared on the wire,
// one entry per header line, so a name sent twice is listed twice. Names the
// recorded order does not account for (added or rewritten after parsing, or no
// order recorded at all) are appended sorted, so a caller with no order
// information still gets a stable fingerprint.
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
