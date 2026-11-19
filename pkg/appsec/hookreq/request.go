// Package hookreq defines `req` for appsec hooks and alert context: a fixed
// subset of *http.Request, so the expr API doesn't grow with net/http.
package hookreq

import (
	"net/http"
	"net/url"
)

type Request struct {
	RemoteAddr string
	Method     string
	Host       string
	RequestURI string
	Proto      string
	ProtoMajor int
	ProtoMinor int
	URL        *url.URL
	Header     http.Header
	// Geo is filled by the appsec engine, not New: this package can't reach the GeoIP databases.
	Geo Geo
}

// Geo is GeoIP data for RemoteAddr. Fields are zero when unknown, so hooks need no nil checks.
type Geo struct {
	Country  string // ISO 3166-1 alpha-2
	ASNumber uint
	ASOrg    string
	Range    string // CIDR
	IsInEU   bool
}

func New(r *http.Request) *Request {
	if r == nil {
		return nil
	}

	return &Request{
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Host:       r.Host,
		RequestURI: r.RequestURI,
		Proto:      r.Proto,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		URL:        r.URL,
		Header:     r.Header,
	}
}

func (r *Request) httpRequest() *http.Request {
	return &http.Request{Header: r.Header}
}

func (r *Request) UserAgent() string {
	return r.httpRequest().UserAgent()
}

func (r *Request) Referer() string {
	return r.httpRequest().Referer()
}

func (r *Request) Cookie(name string) (*http.Cookie, error) {
	return r.httpRequest().Cookie(name)
}

func (r *Request) Cookies() []*http.Cookie {
	return r.httpRequest().Cookies()
}
