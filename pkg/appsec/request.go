package appsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

const (
	URIHeaderName           = "X-Crowdsec-Appsec-Uri"
	VerbHeaderName          = "X-Crowdsec-Appsec-Verb"
	HostHeaderName          = "X-Crowdsec-Appsec-Host"
	IPHeaderName            = "X-Crowdsec-Appsec-Ip"
	APIKeyHeaderName        = "X-Crowdsec-Appsec-Api-Key"
	UserAgentHeaderName     = "X-Crowdsec-Appsec-User-Agent"
	HTTPVersionHeaderName   = "X-Crowdsec-Appsec-Http-Version"
	TransactionIDHeaderName = "X-Crowdsec-Appsec-Transaction-Id"
)

type ParsedRequest struct {
	RemoteAddr           string                  `json:"remote_addr,omitempty"`
	Host                 string                  `json:"host,omitempty"`
	ClientIP             string                  `json:"client_ip,omitempty"`
	URI                  string                  `json:"uri,omitempty"`
	Args                 url.Values              `json:"args,omitempty"`
	ClientHost           string                  `json:"client_host,omitempty"`
	Headers              http.Header             `json:"headers,omitempty"`
	URL                  *url.URL                `json:"url,omitempty"`
	Method               string                  `json:"method,omitempty"`
	Proto                string                  `json:"proto,omitempty"`
	Body                 []byte                  `json:"body,omitempty"`
	TransferEncoding     []string                `json:"transfer_encoding,omitempty"`
	UUID                 string                  `json:"uuid,omitempty"`
	ResponseChannel      chan AppsecTempResponse `json:"-"`
	IsInBand             bool                    `json:"-"`
	IsOutBand            bool                    `json:"-"`
	AppsecEngine         string                  `json:"appsec_engine,omitempty"`
	RemoteAddrNormalized string                  `json:"normalized_remote_addr,omitempty"`
	HTTPRequest          *http.Request           `json:"-"`
	// BodyTruncated is true when the body was larger than the configured limit and was truncated (partial mode).
	BodyTruncated bool `json:"body_truncated,omitempty"`
	// BodySizeExceeded is true when the body exceeded the configured limit and the action is drop.
	// The body is not populated in this case; a fake interruption will be triggered in the runner.
	BodySizeExceeded bool `json:"body_size_exceeded,omitempty"`
}

type ReqDumpFilter struct {
	req                   *ParsedRequest
	HeadersContentFilters []string
	HeadersNameFilters    []string
	HeadersDrop           bool

	BodyDrop bool
	// BodyContentFilters []string TBD

	ArgsContentFilters []string
	ArgsNameFilters    []string
	ArgsDrop           bool
}

func (r *ParsedRequest) DumpRequest(params ...any) *ReqDumpFilter {
	filter := ReqDumpFilter{}
	filter.BodyDrop = true
	filter.HeadersNameFilters = []string{"cookie", "authorization"}
	filter.req = r
	return &filter
}

// clear filters
func (r *ReqDumpFilter) NoFilters() *ReqDumpFilter {
	r2 := ReqDumpFilter{}
	r2.req = r.req
	return &r2
}

func (r *ReqDumpFilter) WithEmptyHeadersFilters() *ReqDumpFilter {
	r.HeadersContentFilters = []string{}
	return r
}

func (r *ReqDumpFilter) WithHeadersContentFilter(filter string) *ReqDumpFilter {
	r.HeadersContentFilters = append(r.HeadersContentFilters, filter)
	return r
}

func (r *ReqDumpFilter) WithHeadersNameFilter(filter string) *ReqDumpFilter {
	r.HeadersNameFilters = append(r.HeadersNameFilters, filter)
	return r
}

func (r *ReqDumpFilter) WithNoHeaders() *ReqDumpFilter {
	r.HeadersDrop = true
	return r
}

func (r *ReqDumpFilter) WithHeaders() *ReqDumpFilter {
	r.HeadersDrop = false
	r.HeadersNameFilters = []string{}
	return r
}

func (r *ReqDumpFilter) WithBody() *ReqDumpFilter {
	r.BodyDrop = false
	return r
}

func (r *ReqDumpFilter) WithNoBody() *ReqDumpFilter {
	r.BodyDrop = true
	return r
}

func (r *ReqDumpFilter) WithEmptyArgsFilters() *ReqDumpFilter {
	r.ArgsContentFilters = []string{}
	return r
}

func (r *ReqDumpFilter) WithArgsContentFilter(filter string) *ReqDumpFilter {
	r.ArgsContentFilters = append(r.ArgsContentFilters, filter)
	return r
}

func (r *ReqDumpFilter) WithArgsNameFilter(filter string) *ReqDumpFilter {
	r.ArgsNameFilters = append(r.ArgsNameFilters, filter)
	return r
}

func (r *ReqDumpFilter) FilterBody(out *ParsedRequest) error {
	if r.BodyDrop {
		return nil
	}
	out.Body = r.req.Body
	return nil
}

func (r *ReqDumpFilter) FilterArgs(out *ParsedRequest) error {
	if r.ArgsDrop {
		return nil
	}

	if len(r.ArgsContentFilters) == 0 && len(r.ArgsNameFilters) == 0 {
		out.Args = r.req.Args
		return nil
	}

	out.Args = make(url.Values)

	for k, vals := range r.req.Args {
		reject := false
		// exclude by match on name
		for _, filter := range r.ArgsNameFilters {
			ok, err := regexp.MatchString("(?i)"+filter, k)
			if err != nil {
				log.Debugf("error while matching string '%s' with '%s': %s", filter, k, err)
				continue
			}

			if ok {
				reject = true
				break
			}
		}

		for _, v := range vals {
			// exclude by content
			for _, filter := range r.ArgsContentFilters {
				ok, err := regexp.MatchString("(?i)"+filter, v)
				if err != nil {
					log.Debugf("error while matching string '%s' with '%s': %s", filter, v, err)
					continue
				}

				if ok {
					reject = true
					break
				}
			}
		}
		// if it was not rejected, let's add it
		if !reject {
			out.Args[k] = vals
		}
	}

	return nil
}

func (r *ReqDumpFilter) FilterHeaders(out *ParsedRequest) error {
	if r.HeadersDrop {
		return nil
	}

	if len(r.HeadersContentFilters) == 0 && len(r.HeadersNameFilters) == 0 {
		out.Headers = r.req.Headers
		return nil
	}

	out.Headers = make(http.Header)

	for k, vals := range r.req.Headers {
		reject := false
		// exclude by match on name
		for _, filter := range r.HeadersNameFilters {
			ok, err := regexp.MatchString("(?i)"+filter, k)
			if err != nil {
				log.Debugf("error while matching string '%s' with '%s': %s", filter, k, err)
				continue
			}

			if ok {
				reject = true
				break
			}
		}

		for _, v := range vals {
			// exclude by content
			for _, filter := range r.HeadersContentFilters {
				ok, err := regexp.MatchString("(?i)"+filter, v)
				if err != nil {
					log.Debugf("error while matching string '%s' with '%s': %s", filter, v, err)
					continue
				}

				if ok {
					reject = true
					break
				}
			}
		}
		// if it was not rejected, let's add it
		if !reject {
			out.Headers[k] = vals
		}
	}

	return nil
}

func (r *ReqDumpFilter) GetFilteredRequest() *ParsedRequest {
	//if there are no filters, we return the original request
	if len(r.HeadersContentFilters) == 0 &&
		len(r.HeadersNameFilters) == 0 &&
		len(r.ArgsContentFilters) == 0 &&
		len(r.ArgsNameFilters) == 0 &&
		!r.BodyDrop && !r.HeadersDrop && !r.ArgsDrop {
		log.Warningf("no filters, returning original request")
		return r.req
	}

	r2 := ParsedRequest{}
	r.FilterHeaders(&r2)
	r.FilterBody(&r2)
	r.FilterArgs(&r2)
	return &r2
}

func (r *ReqDumpFilter) ToJSON() error {
	fd, err := os.CreateTemp("", "crowdsec_req_dump_*.json")
	if err != nil {
		return fmt.Errorf("while creating temp file: %w", err)
	}
	defer fd.Close()
	enc := json.NewEncoder(fd)
	enc.SetIndent("", "  ")

	req := r.GetFilteredRequest()

	log.Tracef("dumping : %+v", req)

	if err := enc.Encode(req); err != nil {
		//Don't clobber the temp directory with empty files
		err2 := os.Remove(fd.Name())
		if err2 != nil {
			log.Errorf("while removing temp file %s: %s", fd.Name(), err)
		}
		return fmt.Errorf("while encoding request: %w", err)
	}
	log.Infof("request dumped to %s", fd.Name())
	return nil
}

// forwardedHeaders are the X-Crowdsec-Appsec-* headers the bouncer supplies to the WAF.
// They carry the original request's metadata and must be stripped before handing the request
// off to Coraza so they aren't mistaken for client-supplied headers.
var forwardedHeaders = []string{
	IPHeaderName,
	HostHeaderName,
	URIHeaderName,
	VerbHeaderName,
	UserAgentHeaderName,
	APIKeyHeaderName,
	HTTPVersionHeaderName,
	TransactionIDHeaderName,
}

// readRequestBody reads r.Body bounded by bodySettings.MaxSize, applies the oversize action, and
// replaces r.Body with a buffered copy of what was kept so downstream code can still read it.
// A timeout on Read is treated as end-of-body — whatever was received is returned without error.
func readRequestBody(r *http.Request, bodySettings BodySettings, logger *log.Entry) (body []byte, truncated, exceeded bool, err error) {
	if r.Body == nil {
		return nil, false, false, nil
	}

	maxSize := bodySettings.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxBodySize
	}

	action := bodySettings.Action
	if action == "" {
		action = BodySizeActionDrop
	}

	// Always read from the actual stream — never trust Content-Length.
	// Read up to maxSize+1 bytes so we can detect whether the body exceeds the limit.
	body, err = io.ReadAll(io.LimitReader(r.Body, maxSize+1))
	var netErr net.Error
	hasTimedout := err != nil && errors.As(err, &netErr) && netErr.Timeout()
	// ErrUnexpectedEOF can occur on POST requests without a body — accept what was read.
	// A net.Error timeout means the read deadline fired; keep what we got and move on.
	// Bouncers are semi-trusted; misbehaving ones would otherwise stall the WAF for seconds.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !hasTimedout {
		return nil, false, false, fmt.Errorf("unable to read body: %w", err)
	}

	if int64(len(body)) > maxSize {
		// Drain remaining bytes so the client doesn't time out waiting for us to finish reading.
		// The LimitReader stopped at maxSize+1, so r.Body may still have unread bytes.
		_, _ = io.Copy(io.Discard, r.Body)

		switch action {
		case BodySizeActionDrop:
			logger.Warnf("request body exceeds limit %d bytes, will drop request", maxSize)
			body = nil
			exceeded = true
		case BodySizeActionAllow:
			logger.Warnf("request body exceeds limit %d bytes, skipping body inspection", maxSize)
			body = nil
		case BodySizeActionPartial:
			logger.Warnf("request body exceeds limit %d bytes, truncating", maxSize)
			body = body[:maxSize]
			truncated = true
		}
	}

	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, truncated, exceeded, nil
}

// applyHTTPVersion parses the 2-character HTTP version header (e.g. "11" for HTTP/1.1, "20" for HTTP/2)
// and updates r.Proto / r.ProtoMajor / r.ProtoMinor. Malformed values are logged and ignored.
func applyHTTPVersion(r *http.Request, version string, logger *log.Entry) {
	if len(version) != 2 ||
		version[0] < '0' || version[0] > '9' ||
		version[1] < '0' || version[1] > '9' {
		logger.Warnf("Invalid value %s for HTTP version header", version)
		return
	}

	r.ProtoMajor = int(version[0] - '0')
	r.ProtoMinor = int(version[1] - '0')
	if r.ProtoMajor == 2 && r.ProtoMinor == 0 {
		r.Proto = "HTTP/2"
	} else {
		r.Proto = "HTTP/" + string(version[0]) + "." + string(version[1])
	}
}

// normalizeRemoteAddr extracts the IP from a "host:port" address and returns its canonical form.
// Returns the input unchanged (and logs) if the value can't be parsed.
func normalizeRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		log.Errorf("Invalid appsec remote IP source %v: %s", remoteAddr, err.Error())
		return remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		log.Errorf("Invalid appsec remote IP address source %v", remoteAddr)
		return remoteAddr
	}
	return ip.String()
}

// Generate a ParsedRequest from a http.Request. ParsedRequest can be consumed by the App security Engine.
// bodySettings controls the maximum body size and what to do when the limit is exceeded.
func NewParsedRequestFromRequest(r *http.Request, logger *log.Entry, bodySettings BodySettings) (ParsedRequest, error) {
	body, bodyTruncated, bodySizeExceeded, err := readRequestBody(r, bodySettings, logger)
	if err != nil {
		return ParsedRequest{}, err
	}

	clientIP := r.Header.Get(IPHeaderName)
	if clientIP == "" {
		return ParsedRequest{}, fmt.Errorf("missing '%s' header", IPHeaderName)
	}

	clientURI := r.Header.Get(URIHeaderName)
	if clientURI == "" {
		return ParsedRequest{}, fmt.Errorf("missing '%s' header", URIHeaderName)
	}

	clientMethod := r.Header.Get(VerbHeaderName)
	if clientMethod == "" {
		return ParsedRequest{}, fmt.Errorf("missing '%s' header", VerbHeaderName)
	}

	clientHost := r.Header.Get(HostHeaderName)
	if clientHost == "" {
		logger.Debugf("missing '%s' header", HostHeaderName)
	}

	userAgent := r.Header.Get(UserAgentHeaderName)

	transactionID := r.Header.Get(TransactionIDHeaderName)
	if transactionID == "" {
		transactionID = uuid.New().String()
	}

	if httpVersion := r.Header.Get(HTTPVersionHeaderName); httpVersion != "" {
		applyHTTPVersion(r, httpVersion, logger)
	} else {
		logger.Debugf("missing '%s' header", HTTPVersionHeaderName)
	}

	for _, h := range forwardedHeaders {
		delete(r.Header, h)
	}

	parsedURL, err := url.Parse(clientURI)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("unable to parse url '%s': %s", clientURI, err)
	}

	originalHTTPRequest := r.Clone(r.Context())
	originalHTTPRequest.Body = io.NopCloser(bytes.NewBuffer(body))
	originalHTTPRequest.RemoteAddr = clientIP
	originalHTTPRequest.RequestURI = clientURI
	originalHTTPRequest.Method = clientMethod
	originalHTTPRequest.Host = clientHost
	originalHTTPRequest.URL = parsedURL
	if userAgent != "" {
		// Override the UA in the original request — this is what the WAF engine sees.
		originalHTTPRequest.Header.Set("User-Agent", userAgent)
		r.Header.Set("User-Agent", userAgent)
	} else {
		// No forwarded UA: drop any UA the remediation layer added, on both copies.
		originalHTTPRequest.Header.Del("User-Agent")
		r.Header.Del("User-Agent")
	}

	if r.RemoteAddr == "@" {
		r.RemoteAddr = "127.0.0.1:65535"
	}

	return ParsedRequest{
		RemoteAddr:           r.RemoteAddr,
		UUID:                 transactionID,
		ClientHost:           clientHost,
		ClientIP:             clientIP,
		URI:                  clientURI,
		Method:               clientMethod,
		Host:                 clientHost,
		Headers:              r.Header,
		URL:                  parsedURL,
		Proto:                r.Proto,
		Body:                 body,
		BodyTruncated:        bodyTruncated,
		BodySizeExceeded:     bodySizeExceeded,
		Args:                 exprhelpers.ParseQuery(parsedURL.RawQuery),
		TransferEncoding:     r.TransferEncoding,
		ResponseChannel:      make(chan AppsecTempResponse),
		RemoteAddrNormalized: normalizeRemoteAddr(r.RemoteAddr),
		HTTPRequest:          originalHTTPRequest,
	}, nil
}
