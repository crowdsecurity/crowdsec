package httpmock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jarcoal/httpmock/internal"
)

const regexpPrefix = "=~"

// NoResponderFound is returned when no responders are found for a
// given HTTP method and URL.
var NoResponderFound = internal.NoResponderFound

var stdMethods = map[string]bool{
	"CONNECT": true, // Section 9.9
	"DELETE":  true, // Section 9.7
	"GET":     true, // Section 9.3
	"HEAD":    true, // Section 9.4
	"OPTIONS": true, // Section 9.2
	"POST":    true, // Section 9.5
	"PUT":     true, // Section 9.6
	"TRACE":   true, // Section 9.8
}

// methodProbablyWrong returns true if method has probably wrong case.
func methodProbablyWrong(method string) bool {
	return !stdMethods[method] && stdMethods[strings.ToUpper(method)]
}

// ConnectionFailure is a responder that returns a connection failure.
// This is the default responder, and is called when no other matching
// responder is found.
func ConnectionFailure(*http.Request) (*http.Response, error) {
	return nil, NoResponderFound
}

// NewMockTransport creates a new *MockTransport with no responders.
func NewMockTransport() *MockTransport {
	return &MockTransport{
		responders:    make(map[internal.RouteKey]Responder),
		callCountInfo: make(map[internal.RouteKey]int),
	}
}

type regexpResponder struct {
	origRx    string
	method    string
	rx        *regexp.Regexp
	responder Responder
}

// MockTransport implements http.RoundTripper, which fulfills single
// http requests issued by an http.Client.  This implementation
// doesn't actually make the call, instead deferring to the registered
// list of responders.
type MockTransport struct {
	// DontCheckMethod disables standard methods check. By default, if
	// a responder is registered using a lower-cased method among CONNECT,
	// DELETE, GET, HEAD, OPTIONS, POST, PUT and TRACE, a panic occurs
	// as it is probably a mistake.
	DontCheckMethod  bool
	mu               sync.RWMutex
	responders       map[internal.RouteKey]Responder
	regexpResponders []regexpResponder
	noResponder      Responder
	callCountInfo    map[internal.RouteKey]int
	totalCallCount   int
}

func (m *MockTransport) findResponder(method string, url *url.URL) (
	responder Responder,
	key, respKey internal.RouteKey,
	submatches []string,
) {
	urlStr := url.String()
	key = internal.RouteKey{
		Method: method,
	}
	for _, getResponder := range []func(internal.RouteKey) (Responder, internal.RouteKey, []string){
		m.responderForKey,       // Exact match
		m.regexpResponderForKey, // Regexp match
	} {
		// try and get a responder that matches the method and URL with
		// query params untouched: http://z.tld/path?q...
		key.URL = urlStr
		responder, respKey, submatches = getResponder(key)
		if responder != nil {
			break
		}

		// if we weren't able to find a responder, try with the URL *and*
		// sorted query params
		query := sortedQuery(url.Query())
		if query != "" {
			// Replace unsorted query params by sorted ones:
			//   http://z.tld/path?sorted_q...
			key.URL = strings.Replace(urlStr, url.RawQuery, query, 1)
			responder, respKey, submatches = getResponder(key)
			if responder != nil {
				break
			}
		}

		// if we weren't able to find a responder, try without any query params
		strippedURL := *url
		strippedURL.RawQuery = ""
		strippedURL.Fragment = ""

		// go1.6 does not handle URL.ForceQuery, so in case it is set in go>1.6,
		// remove the "?" manually if present.
		surl := strings.TrimSuffix(strippedURL.String(), "?")

		hasQueryString := urlStr != surl

		// if the URL contains a querystring then we strip off the
		// querystring and try again: http://z.tld/path
		if hasQueryString {
			key.URL = surl
			responder, respKey, submatches = getResponder(key)
			if responder != nil {
				break
			}
		}

		// if we weren't able to find a responder for the full URL, try with
		// the path part only
		pathAlone := url.Path

		// First with unsorted querystring: /path?q...
		if hasQueryString {
			key.URL = pathAlone + strings.TrimPrefix(urlStr, surl) // concat after-path part
			responder, respKey, submatches = getResponder(key)
			if responder != nil {
				break
			}

			// Then with sorted querystring: /path?sorted_q...
			key.URL = pathAlone + "?" + sortedQuery(url.Query())
			if url.Fragment != "" {
				key.URL += "#" + url.Fragment
			}
			responder, respKey, submatches = getResponder(key)
			if responder != nil {
				break
			}
		}

		// Then using path alone: /path
		key.URL = pathAlone
		responder, respKey, submatches = getResponder(key)
		if responder != nil {
			break
		}
	}
	return
}

// RoundTrip receives HTTP requests and routes them to the appropriate
// responder.  It is required to implement the http.RoundTripper
// interface.  You will not interact with this directly, instead the
// *http.Client you are using will call it for you.
func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	method := req.Method
	if method == "" {
		// http.Request.Method is documented to default to GET:
		method = http.MethodGet
	}

	var suggestedMethod string

	responder, key, respKey, submatches := m.findResponder(method, req.URL)
	if responder == nil {
		// Responder not found, try to detect some common user mistakes on method
		var altResp Responder
		var altKey internal.RouteKey
		if methodProbablyWrong(method) {
			// Get → GET
			altResp, _, altKey, _ = m.findResponder(strings.ToUpper(method), req.URL)
		}
		if altResp == nil {
			// Search for any other method
			altResp, _, altKey, _ = m.findResponder("", req.URL)
		}
		if altResp != nil {
			suggestedMethod = altKey.Method
		}
	}

	m.mu.Lock()
	// if we found a responder, call it
	if responder != nil {
		m.callCountInfo[key]++
		if key != respKey {
			m.callCountInfo[respKey]++
		}
		m.totalCallCount++
	} else if m.noResponder != nil {
		// we didn't find a responder, so fire the 'no responder' responder
		m.callCountInfo[internal.NoResponder]++
		m.totalCallCount++
		// give a hint to NewNotFoundResponder() if it is a possible method error
		if suggestedMethod != "" {
			req = req.WithContext(context.WithValue(req.Context(), suggestedMethodKey, suggestedMethod))
		}
		responder = m.noResponder
	}
	m.mu.Unlock()

	if responder == nil {
		if suggestedMethod != "" {
			return nil, internal.NewErrorNoResponderFoundWrongMethod(method, suggestedMethod)
		}
		return ConnectionFailure(req)
	}
	return runCancelable(responder, internal.SetSubmatches(req, submatches))
}

// NumResponders returns the number of responders currently in use.
func (m *MockTransport) NumResponders() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.responders) + len(m.regexpResponders)
}

func runCancelable(responder Responder, req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if req.Cancel == nil && ctx.Done() == nil { // nolint: staticcheck
		resp, err := responder(req)
		return resp, internal.CheckStackTracer(req, err)
	}

	// Set up a goroutine that translates a close(req.Cancel) into a
	// "request canceled" error, and another one that runs the
	// responder. Then race them: first to the result channel wins.

	type result struct {
		response *http.Response
		err      error
	}
	resultch := make(chan result, 1)
	done := make(chan struct{}, 1)

	go func() {
		select {
		case <-req.Cancel: // nolint: staticcheck
			resultch <- result{
				response: nil,
				err:      errors.New("request canceled"),
			}
		case <-ctx.Done():
			resultch <- result{
				response: nil,
				err:      ctx.Err(),
			}
		case <-done:
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				resultch <- result{
					response: nil,
					err:      fmt.Errorf("panic in responder: got %q", err),
				}
			}
		}()

		response, err := responder(req)
		resultch <- result{
			response: response,
			err:      err,
		}
	}()

	r := <-resultch

	// if a cancel() issued from context.WithCancel() or a
	// close(req.Cancel) are never coming, we'll need to unblock the
	// first goroutine.
	done <- struct{}{}

	return r.response, internal.CheckStackTracer(req, r.err)
}

// responderForKey returns a responder for a given key.
func (m *MockTransport) responderForKey(key internal.RouteKey) (Responder, internal.RouteKey, []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if key.Method != "" {
		return m.responders[key], key, nil
	}

	for k, resp := range m.responders {
		if key.URL == k.URL {
			return resp, k, nil
		}
	}
	return nil, key, nil
}

// responderForKeyUsingRegexp returns the first responder matching a
// given key using regexps.
func (m *MockTransport) regexpResponderForKey(key internal.RouteKey) (Responder, internal.RouteKey, []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, regInfo := range m.regexpResponders {
		if key.Method == "" || regInfo.method == key.Method {
			if sm := regInfo.rx.FindStringSubmatch(key.URL); sm != nil {
				if len(sm) == 1 {
					sm = nil
				} else {
					sm = sm[1:]
				}
				return regInfo.responder, internal.RouteKey{
					Method: regInfo.method,
					URL:    regInfo.origRx,
				}, sm
			}
		}
	}
	return nil, key, nil
}

func isRegexpURL(url string) bool {
	return strings.HasPrefix(url, regexpPrefix)
}
func (m *MockTransport) checkMethod(method string) {
	if !m.DontCheckMethod && methodProbablyWrong(method) {
		panic(fmt.Sprintf("You probably want to use method %q instead of %q? If not and so want to disable this check, set MockTransport.DontCheckMethod field to true",
			strings.ToUpper(method),
			method,
		))
	}
}

// RegisterResponder adds a new responder, associated with a given
// HTTP method and URL (or path).
//
// When a request comes in that matches, the responder is called and
// the response returned to the client.
//
// If url contains query parameters, their order matters as well as
// their content. All following URLs are here considered as different:
//   http://z.tld?a=1&b=1
//   http://z.tld?b=1&a=1
//   http://z.tld?a&b
//   http://z.tld?a=&b=
//
// If url begins with "=~", the following chars are considered as a
// regular expression. If this regexp can not be compiled, it panics.
// Note that the "=~" prefix remains in statistics returned by
// GetCallCountInfo(). As 2 regexps can match the same URL, the regexp
// responders are tested in the order they are registered. Registering
// an already existing regexp responder (same method & same regexp
// string) replaces its responder, but does not change its position.
//
// Registering an already existing responder resets the corresponding
// statistics as returned by GetCallCountInfo().
//
// Registering a nil Responder removes the existing one and the
// corresponding statistics as returned by GetCallCountInfo(). It does
// nothing if it does not already exist.
//
// See RegisterRegexpResponder() to directly pass a *regexp.Regexp.
//
// Example:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     defer httpmock.DeactivateAndReset()
//
//     httpmock.RegisterResponder("GET", "http://example.com/",
//       httpmock.NewStringResponder(200, "hello world"))
//
//     httpmock.RegisterResponder("GET", "/path/only",
//       httpmock.NewStringResponder("any host hello world", 200))
//
//     httpmock.RegisterResponder("GET", `=~^/item/id/\d+\z`,
//       httpmock.NewStringResponder("any item get", 200))
//
//     // requests to http://example.com/ now return "hello world" and
//     // requests to any host with path /path/only return "any host hello world"
//     // requests to any host with path matching ^/item/id/\d+\z regular expression return "any item get"
//   }
//
// If method is a lower-cased version of CONNECT, DELETE, GET, HEAD,
// OPTIONS, POST, PUT or TRACE, a panics occurs to notice the possible
// mistake. This panic can be disabled by setting m.DontCheckMethod to
// true prior to this call.
func (m *MockTransport) RegisterResponder(method, url string, responder Responder) {
	m.checkMethod(method)

	if isRegexpURL(url) {
		m.registerRegexpResponder(regexpResponder{
			origRx:    url,
			method:    method,
			rx:        regexp.MustCompile(url[2:]),
			responder: responder,
		})
		return
	}

	key := internal.RouteKey{
		Method: method,
		URL:    url,
	}

	m.mu.Lock()
	if responder == nil {
		delete(m.responders, key)
		delete(m.callCountInfo, key)
	} else {
		m.responders[key] = responder
		m.callCountInfo[key] = 0
	}
	m.mu.Unlock()
}

func (m *MockTransport) registerRegexpResponder(rxResp regexpResponder) {
	m.mu.Lock()
	defer m.mu.Unlock()

found:
	for {
		for i, rr := range m.regexpResponders {
			if rr.method == rxResp.method && rr.origRx == rxResp.origRx {
				if rxResp.responder == nil {
					copy(m.regexpResponders[:i], m.regexpResponders[i+1:])
					m.regexpResponders[len(m.regexpResponders)-1] = regexpResponder{}
					m.regexpResponders = m.regexpResponders[:len(m.regexpResponders)-1]
				} else {
					m.regexpResponders[i] = rxResp
				}
				break found
			}
		}
		if rxResp.responder != nil {
			m.regexpResponders = append(m.regexpResponders, rxResp)
		}
		break // nolint: staticcheck
	}

	key := internal.RouteKey{
		Method: rxResp.method,
		URL:    rxResp.origRx,
	}
	if rxResp.responder == nil {
		delete(m.callCountInfo, key)
	} else {
		m.callCountInfo[key] = 0
	}
}

// RegisterRegexpResponder adds a new responder, associated with a given
// HTTP method and URL (or path) regular expression.
//
// When a request comes in that matches, the responder is called and
// the response returned to the client.
//
// As 2 regexps can match the same URL, the regexp responders are
// tested in the order they are registered. Registering an already
// existing regexp responder (same method & same regexp string)
// replaces its responder, but does not change its position, and
// resets the corresponding statistics as returned by GetCallCountInfo().
//
// Registering a nil Responder removes the existing one and the
// corresponding statistics as returned by GetCallCountInfo(). It does
// nothing if it does not already exist.
//
// A "=~" prefix is added to the stringified regexp in the statistics
// returned by GetCallCountInfo().
//
// See RegisterResponder function and the "=~" prefix in its url
// parameter to avoid compiling the regexp by yourself.
//
// If method is a lower-cased version of CONNECT, DELETE, GET, HEAD,
// OPTIONS, POST, PUT or TRACE, a panics occurs to notice the possible
// mistake. This panic can be disabled by setting m.DontCheckMethod to
// true prior to this call.
func (m *MockTransport) RegisterRegexpResponder(method string, urlRegexp *regexp.Regexp, responder Responder) {
	m.checkMethod(method)

	m.registerRegexpResponder(regexpResponder{
		origRx:    regexpPrefix + urlRegexp.String(),
		method:    method,
		rx:        urlRegexp,
		responder: responder,
	})
}

// RegisterResponderWithQuery is same as RegisterResponder, but it
// doesn't depend on query items order.
//
// If query is non-nil, its type can be:
//   url.Values
//   map[string]string
//   string, a query string like "a=12&a=13&b=z&c" (see net/url.ParseQuery function)
//
// If the query type is not recognized or the string cannot be parsed
// using net/url.ParseQuery, a panic() occurs.
//
// Unlike RegisterResponder, path cannot be prefixed by "=~" to say it
// is a regexp. If it is, a panic occurs.
//
// Registering an already existing responder resets the corresponding
// statistics as returned by GetCallCountInfo().
//
// Registering a nil Responder removes the existing one and the
// corresponding statistics as returned by GetCallCountInfo(). It does
// nothing if it does not already exist.
//
// If method is a lower-cased version of CONNECT, DELETE, GET, HEAD,
// OPTIONS, POST, PUT or TRACE, a panics occurs to notice the possible
// mistake. This panic can be disabled by setting m.DontCheckMethod to
// true prior to this call.
func (m *MockTransport) RegisterResponderWithQuery(method, path string, query interface{}, responder Responder) {
	if isRegexpURL(path) {
		panic(`path begins with "=~", RegisterResponder should be used instead of RegisterResponderWithQuery`)
	}

	var mapQuery url.Values
	switch q := query.(type) {
	case url.Values:
		mapQuery = q

	case map[string]string:
		mapQuery = make(url.Values, len(q))
		for key, e := range q {
			mapQuery[key] = []string{e}
		}

	case string:
		var err error
		mapQuery, err = url.ParseQuery(q)
		if err != nil {
			panic("RegisterResponderWithQuery bad query string: " + err.Error())
		}

	default:
		if query != nil {
			panic(fmt.Sprintf("RegisterResponderWithQuery bad query type %T. Only url.Values, map[string]string and string are allowed", query))
		}
	}

	if queryString := sortedQuery(mapQuery); queryString != "" {
		path += "?" + queryString
	}
	m.RegisterResponder(method, path, responder)
}

func sortedQuery(m url.Values) string {
	if len(m) == 0 {
		return ""
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b bytes.Buffer
	var values []string // nolint: prealloc

	for _, k := range keys {
		// Do not alter the passed url.Values
		values = append(values, m[k]...)
		sort.Strings(values)

		k = url.QueryEscape(k)

		for _, v := range values {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			fmt.Fprintf(&b, "%v=%v", k, url.QueryEscape(v))
		}

		values = values[:0]
	}

	return b.String()
}

// RegisterNoResponder is used to register a responder that is called
// if no other responder is found.  The default is httpmock.ConnectionFailure
// that returns an error able to indicate a possible method mismatch.
//
// Use it in conjunction with NewNotFoundResponder to ensure that all
// routes have been mocked:
//
//   import (
//     "testing"
//     "github.com/jarcoal/httpmock"
//   )
//   ...
//   func TestMyApp(t *testing.T) {
//      ...
//      // Calls testing.Fatal with the name of Responder-less route and
//      // the stack trace of the call.
//      httpmock.RegisterNoResponder(httpmock.NewNotFoundResponder(t.Fatal))
//
// Will abort the current test and print something like:
//   transport_test.go:735: Called from net/http.Get()
//         at /go/src/github.com/jarcoal/httpmock/transport_test.go:714
//       github.com/jarcoal/httpmock.TestCheckStackTracer()
//         at /go/src/testing/testing.go:865
//       testing.tRunner()
//         at /go/src/runtime/asm_amd64.s:1337
//
// If responder is passed as nil, the default behavior
// (httpmock.ConnectionFailure) is re-enabled.
func (m *MockTransport) RegisterNoResponder(responder Responder) {
	m.mu.Lock()
	m.noResponder = responder
	m.mu.Unlock()
}

// Reset removes all registered responders (including the no
// responder) from the MockTransport. It zeroes call counters too.
func (m *MockTransport) Reset() {
	m.mu.Lock()
	m.responders = make(map[internal.RouteKey]Responder)
	m.regexpResponders = nil
	m.noResponder = nil
	m.callCountInfo = make(map[internal.RouteKey]int)
	m.totalCallCount = 0
	m.mu.Unlock()
}

// ZeroCallCounters zeroes call counters without touching registered responders.
func (m *MockTransport) ZeroCallCounters() {
	m.mu.Lock()
	for k := range m.callCountInfo {
		m.callCountInfo[k] = 0
	}
	m.totalCallCount = 0
	m.mu.Unlock()
}

// GetCallCountInfo gets the info on all the calls httpmock has caught
// since it was activated or reset. The info is returned as a map of
// the calling keys with the number of calls made to them as their
// value. The key is the method, a space, and the url all concatenated
// together.
//
// As a special case, regexp responders generate 2 entries for each
// call. One for the call caught and the other for the rule that
// matched. For example:
//   RegisterResponder("GET", `=~z\.com\z`, NewStringResponder(200, "body"))
//   http.Get("http://z.com")
//
// will generate the following result:
//   map[string]int{
//     `GET http://z.com`: 1,
//     `GET =~z\.com\z`:   1,
//   }
func (m *MockTransport) GetCallCountInfo() map[string]int {
	m.mu.RLock()
	res := make(map[string]int, len(m.callCountInfo))
	for k, v := range m.callCountInfo {
		res[k.String()] = v
	}
	m.mu.RUnlock()
	return res
}

// GetTotalCallCount returns the totalCallCount.
func (m *MockTransport) GetTotalCallCount() int {
	m.mu.RLock()
	count := m.totalCallCount
	m.mu.RUnlock()
	return count
}

// DefaultTransport is the default mock transport used by Activate,
// Deactivate, Reset, DeactivateAndReset, RegisterResponder, and
// RegisterNoResponder.
var DefaultTransport = NewMockTransport()

// InitialTransport is a cache of the original transport used so we
// can put it back when Deactivate is called.
var InitialTransport = http.DefaultTransport

// oldClients is used to handle custom http clients (i.e clients other
// than http.DefaultClient).
var oldClients = map[*http.Client]http.RoundTripper{}

// Activate starts the mock environment.  This should be called before
// your tests run.  Under the hood this replaces the Transport on the
// http.DefaultClient with httpmock.DefaultTransport.
//
// To enable mocks for a test, simply activate at the beginning of a test:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     // all http requests using http.DefaultTransport will now be intercepted
//   }
//
// If you want all of your tests in a package to be mocked, just call
// Activate from init():
//   func init() {
//     httpmock.Activate()
//   }
//
// or using a TestMain function:
//   func TestMain(m *testing.M) {
//     httpmock.Activate()
//     os.Exit(m.Run())
//   }
func Activate() {
	if Disabled() {
		return
	}

	// make sure that if Activate is called multiple times it doesn't
	// overwrite the InitialTransport with a mock transport.
	if http.DefaultTransport != DefaultTransport {
		InitialTransport = http.DefaultTransport
	}

	http.DefaultTransport = DefaultTransport
}

// ActivateNonDefault starts the mock environment with a non-default
// http.Client.  This emulates the Activate function, but allows for
// custom clients that do not use http.DefaultTransport
//
// To enable mocks for a test using a custom client, activate at the
// beginning of a test:
//   client := &http.Client{Transport: &http.Transport{TLSHandshakeTimeout: 60 * time.Second}}
//   httpmock.ActivateNonDefault(client)
func ActivateNonDefault(client *http.Client) {
	if Disabled() {
		return
	}

	// save the custom client & it's RoundTripper
	if _, ok := oldClients[client]; !ok {
		oldClients[client] = client.Transport
	}
	client.Transport = DefaultTransport
}

// GetCallCountInfo gets the info on all the calls httpmock has caught
// since it was activated or reset. The info is returned as a map of
// the calling keys with the number of calls made to them as their
// value. The key is the method, a space, and the url all concatenated
// together.
//
// As a special case, regexp responders generate 2 entries for each
// call. One for the call caught and the other for the rule that
// matched. For example:
//   RegisterResponder("GET", `=~z\.com\z`, NewStringResponder(200, "body"))
//   http.Get("http://z.com")
//
// will generate the following result:
//   map[string]int{
//     `GET http://z.com`: 1,
//     `GET =~z\.com\z`:   1,
//   }
func GetCallCountInfo() map[string]int {
	return DefaultTransport.GetCallCountInfo()
}

// GetTotalCallCount gets the total number of calls httpmock has taken
// since it was activated or reset.
func GetTotalCallCount() int {
	return DefaultTransport.GetTotalCallCount()
}

// Deactivate shuts down the mock environment.  Any HTTP calls made
// after this will use a live transport.
//
// Usually you'll call it in a defer right after activating the mock
// environment:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     defer httpmock.Deactivate()
//
//     // when this test ends, the mock environment will close
//   }
//
// Since go 1.14 you can also use (*testing.T).Cleanup() method as in:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     t.Cleanup(httpmock.Deactivate)
//
//     // when this test ends, the mock environment will close
//   }
//
// useful in test helpers to save your callers from calling defer themselves.
func Deactivate() {
	if Disabled() {
		return
	}
	http.DefaultTransport = InitialTransport

	// reset the custom clients to use their original RoundTripper
	for oldClient, oldTransport := range oldClients {
		oldClient.Transport = oldTransport
		delete(oldClients, oldClient)
	}
}

// Reset removes any registered mocks and returns the mock
// environment to its initial state. It zeroes call counters too.
func Reset() {
	DefaultTransport.Reset()
}

// ZeroCallCounters zeroes call counters without touching registered responders.
func ZeroCallCounters() {
	DefaultTransport.ZeroCallCounters()
}

// DeactivateAndReset is just a convenience method for calling
// Deactivate() and then Reset().
//
// Happy deferring!
func DeactivateAndReset() {
	Deactivate()
	Reset()
}

// RegisterResponder adds a new responder, associated with a given
// HTTP method and URL (or path).
//
// When a request comes in that matches, the responder is called and
// the response returned to the client.
//
// If url contains query parameters, their order matters as well as
// their content. All following URLs are here considered as different:
//   http://z.tld?a=1&b=1
//   http://z.tld?b=1&a=1
//   http://z.tld?a&b
//   http://z.tld?a=&b=
//
// If url begins with "=~", the following chars are considered as a
// regular expression. If this regexp can not be compiled, it panics.
// Note that the "=~" prefix remains in statistics returned by
// GetCallCountInfo(). As 2 regexps can match the same URL, the regexp
// responders are tested in the order they are registered. Registering
// an already existing regexp responder (same method & same regexp
// string) replaces its responder, but does not change its position.
//
// Registering an already existing responder resets the corresponding
// statistics as returned by GetCallCountInfo().
//
// Registering a nil Responder removes the existing one and the
// corresponding statistics as returned by GetCallCountInfo(). It does
// nothing if it does not already exist.
//
// See RegisterRegexpResponder() to directly pass a *regexp.Regexp.
//
// Example:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     defer httpmock.DeactivateAndReset()
//
//     httpmock.RegisterResponder("GET", "http://example.com/",
//       httpmock.NewStringResponder(200, "hello world"))
//
//     httpmock.RegisterResponder("GET", "/path/only",
//       httpmock.NewStringResponder("any host hello world", 200))
//
//     httpmock.RegisterResponder("GET", `=~^/item/id/\d+\z`,
//       httpmock.NewStringResponder("any item get", 200))
//
//     // requests to http://example.com/ now return "hello world" and
//     // requests to any host with path /path/only return "any host hello world"
//     // requests to any host with path matching ^/item/id/\d+\z regular expression return "any item get"
//   }
//
// If method is a lower-cased version of CONNECT, DELETE, GET, HEAD,
// OPTIONS, POST, PUT or TRACE, a panics occurs to notice the possible
// mistake. This panic can be disabled by setting
// DefaultTransport.DontCheckMethod to true prior to this call.
func RegisterResponder(method, url string, responder Responder) {
	DefaultTransport.RegisterResponder(method, url, responder)
}

// RegisterRegexpResponder adds a new responder, associated with a given
// HTTP method and URL (or path) regular expression.
//
// When a request comes in that matches, the responder is called and
// the response returned to the client.
//
// As 2 regexps can match the same URL, the regexp responders are
// tested in the order they are registered. Registering an already
// existing regexp responder (same method & same regexp string)
// replaces its responder, but does not change its position, and
// resets the corresponding statistics as returned by GetCallCountInfo().
//
// Registering a nil Responder removes the existing one and the
// corresponding statistics as returned by GetCallCountInfo(). It does
// nothing if it does not already exist.
//
// A "=~" prefix is added to the stringified regexp in the statistics
// returned by GetCallCountInfo().
//
// See RegisterResponder function and the "=~" prefix in its url
// parameter to avoid compiling the regexp by yourself.
//
// If method is a lower-cased version of CONNECT, DELETE, GET, HEAD,
// OPTIONS, POST, PUT or TRACE, a panics occurs to notice the possible
// mistake. This panic can be disabled by setting
// DefaultTransport.DontCheckMethod to true prior to this call.
func RegisterRegexpResponder(method string, urlRegexp *regexp.Regexp, responder Responder) {
	DefaultTransport.RegisterRegexpResponder(method, urlRegexp, responder)
}

// RegisterResponderWithQuery it is same as RegisterResponder, but
// doesn't depends on query items order.
//
// query type can be:
//   url.Values
//   map[string]string
//   string, a query string like "a=12&a=13&b=z&c" (see net/url.ParseQuery function)
//
// If the query type is not recognized or the string cannot be parsed
// using net/url.ParseQuery, a panic() occurs.
//
// Unlike RegisterResponder, path cannot be prefixed by "=~" to say it
// is a regexp. If it is, a panic occurs.
//
// Registering an already existing responder resets the corresponding
// statistics as returned by GetCallCountInfo().
//
// Registering a nil Responder removes the existing one and the
// corresponding statistics as returned by GetCallCountInfo(). It does
// nothing if it does not already exist.
//
// Example using a net/url.Values:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     defer httpmock.DeactivateAndReset()
//
//     expectedQuery := net.Values{
//       "a": []string{"3", "1", "8"},
//       "b": []string{"4", "2"},
//     }
//     httpmock.RegisterResponderWithQueryValues(
//       "GET", "http://example.com/", expectedQuery,
//       httpmock.NewStringResponder("hello world", 200))
//
//     // requests to http://example.com?a=1&a=3&a=8&b=2&b=4
//     //      and to http://example.com?b=4&a=2&b=2&a=8&a=1
//     // now return 'hello world'
//   }
//
// or using a map[string]string:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     defer httpmock.DeactivateAndReset()
//
//     expectedQuery := map[string]string{
//       "a": "1",
//       "b": "2"
//     }
//     httpmock.RegisterResponderWithQuery(
//       "GET", "http://example.com/", expectedQuery,
//       httpmock.NewStringResponder("hello world", 200))
//
//     // requests to http://example.com?a=1&b=2 and http://example.com?b=2&a=1 now return 'hello world'
//   }
//
// or using a query string:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     defer httpmock.DeactivateAndReset()
//
//     expectedQuery := "a=3&b=4&b=2&a=1&a=8"
//     httpmock.RegisterResponderWithQueryValues(
//       "GET", "http://example.com/", expectedQuery,
//       httpmock.NewStringResponder("hello world", 200))
//
//     // requests to http://example.com?a=1&a=3&a=8&b=2&b=4
//     //      and to http://example.com?b=4&a=2&b=2&a=8&a=1
//     // now return 'hello world'
//   }
//
// If method is a lower-cased version of CONNECT, DELETE, GET, HEAD,
// OPTIONS, POST, PUT or TRACE, a panics occurs to notice the possible
// mistake. This panic can be disabled by setting
// DefaultTransport.DontCheckMethod to true prior to this call.
func RegisterResponderWithQuery(method, path string, query interface{}, responder Responder) {
	DefaultTransport.RegisterResponderWithQuery(method, path, query, responder)
}

// RegisterNoResponder adds a mock that is called whenever a request
// for an unregistered URL is received.  The default behavior is to
// return a connection error.
//
// In some cases you may not want all URLs to be mocked, in which case
// you can do this:
//   func TestFetchArticles(t *testing.T) {
//     httpmock.Activate()
//     defer httpmock.DeactivateAndReset()
//     httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)
//
//     // any requests that don't have a registered URL will be fetched normally
//   }
func RegisterNoResponder(responder Responder) {
	DefaultTransport.RegisterNoResponder(responder)
}

// ErrSubmatchNotFound is the error returned by GetSubmatch* functions
// when the given submatch index cannot be found.
var ErrSubmatchNotFound = errors.New("submatch not found")

// GetSubmatch has to be used in Responders installed by
// RegisterRegexpResponder or RegisterResponder + "=~" URL prefix. It
// allows to retrieve the n-th submatch of the matching regexp, as a
// string. Example:
//   RegisterResponder("GET", `=~^/item/name/([^/]+)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       name, err := GetSubmatch(req, 1) // 1=first regexp submatch
//       if err != nil {
//         return nil, err
//       }
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":   123,
//         "name": name,
//       })
//     })
//
// It panics if n < 1. See MustGetSubmatch to avoid testing the
// returned error.
func GetSubmatch(req *http.Request, n int) (string, error) {
	if n <= 0 {
		panic(fmt.Sprintf("getting submatches starts at 1, not %d", n))
	}
	n--

	submatches := internal.GetSubmatches(req)
	if n >= len(submatches) {
		return "", ErrSubmatchNotFound
	}
	return submatches[n], nil
}

// GetSubmatchAsInt has to be used in Responders installed by
// RegisterRegexpResponder or RegisterResponder + "=~" URL prefix. It
// allows to retrieve the n-th submatch of the matching regexp, as an
// int64. Example:
//   RegisterResponder("GET", `=~^/item/id/(\d+)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       id, err := GetSubmatchAsInt(req, 1) // 1=first regexp submatch
//       if err != nil {
//         return nil, err
//       }
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":   id,
//         "name": "The beautiful name",
//       })
//     })
//
// It panics if n < 1. See MustGetSubmatchAsInt to avoid testing the
// returned error.
func GetSubmatchAsInt(req *http.Request, n int) (int64, error) {
	sm, err := GetSubmatch(req, n)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(sm, 10, 64)
}

// GetSubmatchAsUint has to be used in Responders installed by
// RegisterRegexpResponder or RegisterResponder + "=~" URL prefix. It
// allows to retrieve the n-th submatch of the matching regexp, as a
// uint64. Example:
//   RegisterResponder("GET", `=~^/item/id/(\d+)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       id, err := GetSubmatchAsUint(req, 1) // 1=first regexp submatch
//       if err != nil {
//         return nil, err
//       }
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":   id,
//         "name": "The beautiful name",
//       })
//     })
//
// It panics if n < 1. See MustGetSubmatchAsUint to avoid testing the
// returned error.
func GetSubmatchAsUint(req *http.Request, n int) (uint64, error) {
	sm, err := GetSubmatch(req, n)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(sm, 10, 64)
}

// GetSubmatchAsFloat has to be used in Responders installed by
// RegisterRegexpResponder or RegisterResponder + "=~" URL prefix. It
// allows to retrieve the n-th submatch of the matching regexp, as a
// float64. Example:
//   RegisterResponder("PATCH", `=~^/item/id/\d+\?height=(\d+(?:\.\d*)?)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       height, err := GetSubmatchAsFloat(req, 1) // 1=first regexp submatch
//       if err != nil {
//         return nil, err
//       }
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":     id,
//         "name":   "The beautiful name",
//         "height": height,
//       })
//     })
//
// It panics if n < 1. See MustGetSubmatchAsFloat to avoid testing the
// returned error.
func GetSubmatchAsFloat(req *http.Request, n int) (float64, error) {
	sm, err := GetSubmatch(req, n)
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(sm, 64)
}

// MustGetSubmatch works as GetSubmatch except that it panics in case
// of error (submatch not found). It has to be used in Responders
// installed by RegisterRegexpResponder or RegisterResponder + "=~"
// URL prefix. It allows to retrieve the n-th submatch of the matching
// regexp, as a string. Example:
//   RegisterResponder("GET", `=~^/item/name/([^/]+)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       name := MustGetSubmatch(req, 1) // 1=first regexp submatch
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":   123,
//         "name": name,
//       })
//     })
//
// It panics if n < 1.
func MustGetSubmatch(req *http.Request, n int) string {
	s, err := GetSubmatch(req, n)
	if err != nil {
		panic("GetSubmatch failed: " + err.Error())
	}
	return s
}

// MustGetSubmatchAsInt works as GetSubmatchAsInt except that it
// panics in case of error (submatch not found or invalid int64
// format). It has to be used in Responders installed by
// RegisterRegexpResponder or RegisterResponder + "=~" URL prefix. It
// allows to retrieve the n-th submatch of the matching regexp, as an
// int64. Example:
//   RegisterResponder("GET", `=~^/item/id/(\d+)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       id := MustGetSubmatchAsInt(req, 1) // 1=first regexp submatch
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":   id,
//         "name": "The beautiful name",
//       })
//     })
//
// It panics if n < 1.
func MustGetSubmatchAsInt(req *http.Request, n int) int64 {
	i, err := GetSubmatchAsInt(req, n)
	if err != nil {
		panic("GetSubmatchAsInt failed: " + err.Error())
	}
	return i
}

// MustGetSubmatchAsUint works as GetSubmatchAsUint except that it
// panics in case of error (submatch not found or invalid uint64
// format). It has to be used in Responders installed by
// RegisterRegexpResponder or RegisterResponder + "=~" URL prefix. It
// allows to retrieve the n-th submatch of the matching regexp, as a
// uint64. Example:
//   RegisterResponder("GET", `=~^/item/id/(\d+)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       id, err := MustGetSubmatchAsUint(req, 1) // 1=first regexp submatch
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":   id,
//         "name": "The beautiful name",
//       })
//     })
//
// It panics if n < 1.
func MustGetSubmatchAsUint(req *http.Request, n int) uint64 {
	u, err := GetSubmatchAsUint(req, n)
	if err != nil {
		panic("GetSubmatchAsUint failed: " + err.Error())
	}
	return u
}

// MustGetSubmatchAsFloat works as GetSubmatchAsFloat except that it
// panics in case of error (submatch not found or invalid float64
// format). It has to be used in Responders installed by
// RegisterRegexpResponder or RegisterResponder + "=~" URL prefix. It
// allows to retrieve the n-th submatch of the matching regexp, as a
// float64. Example:
//   RegisterResponder("PATCH", `=~^/item/id/\d+\?height=(\d+(?:\.\d*)?)\z`,
//     func(req *http.Request) (*http.Response, error) {
//       height := MustGetSubmatchAsFloat(req, 1) // 1=first regexp submatch
//       return NewJsonResponse(200, map[string]interface{}{
//         "id":     id,
//         "name":   "The beautiful name",
//         "height": height,
//       })
//     })
//
// It panics if n < 1.
func MustGetSubmatchAsFloat(req *http.Request, n int) float64 {
	f, err := GetSubmatchAsFloat(req, n)
	if err != nil {
		panic("GetSubmatchAsFloat failed: " + err.Error())
	}
	return f
}
