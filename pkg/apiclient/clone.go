package apiclient

import (
	"bytes"
	"io"
	"net/http"
	"slices"
)

// cloneRequest returns a clone of the provided *http.Request. The clone is a
// shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))

	for k, s := range r.Header {
		r2.Header[k] = slices.Clone(s)
	}

	if r.Body != nil {
		var b bytes.Buffer

		b.ReadFrom(r.Body)

		r.Body = io.NopCloser(&b)
		r2.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
	}

	return r2
}
