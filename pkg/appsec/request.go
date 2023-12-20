package appsec

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	URIHeaderName    = "X-Crowdsec-Appsec-Uri"
	VerbHeaderName   = "X-Crowdsec-Appsec-Verb"
	HostHeaderName   = "X-Crowdsec-Appsec-Host"
	IPHeaderName     = "X-Crowdsec-Appsec-Ip"
	APIKeyHeaderName = "X-Crowdsec-Appsec-Api-Key"
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
	Tx                   ExtendedTransaction     `json:"transaction,omitempty"`
	ResponseChannel      chan AppsecTempResponse `json:"-"`
	IsInBand             bool                    `json:"-"`
	IsOutBand            bool                    `json:"-"`
	AppsecEngine         string                  `json:"appsec_engine,omitempty"`
	RemoteAddrNormalized string                  `json:"normalized_remote_addr,omitempty"`
}

type ReqDumpFilter struct {
	req                   *ParsedRequest
	HeadersContentFilters []string
	HeadersNameFilters    []string
	HeadersDrop           bool

	BodyDrop bool
	//BodyContentFilters []string TBD

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
		//exclude by match on name
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
			//exclude by content
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
		//if it was not rejected, let's add it
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
		//exclude by match on name
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
			//exclude by content
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
		//if it was not rejected, let's add it
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

	log.Warningf("dumping : %+v", req)

	if err := enc.Encode(req); err != nil {
		return fmt.Errorf("while encoding request: %w", err)
	}
	log.Warningf("request dumped to %s", fd.Name())
	return nil
}

// Generate a ParsedRequest from a http.Request. ParsedRequest can be consumed by the App security Engine
func NewParsedRequestFromRequest(r *http.Request) (ParsedRequest, error) {
	var err error
	contentLength := r.ContentLength
	if contentLength < 0 {
		contentLength = 0
	}
	body := make([]byte, contentLength)

	if r.Body != nil {
		_, err = io.ReadFull(r.Body, body)
		if err != nil {
			return ParsedRequest{}, fmt.Errorf("unable to read body: %s", err)
		}
	}

	// the real source of the request is set in 'x-client-ip'
	clientIP := r.Header.Get(IPHeaderName)
	if clientIP == "" {
		return ParsedRequest{}, fmt.Errorf("missing '%s' header", IPHeaderName)
	}
	// the real target Host of the request is set in 'x-client-host'
	clientHost := r.Header.Get(HostHeaderName)
	if clientHost == "" {
		return ParsedRequest{}, fmt.Errorf("missing '%s' header", HostHeaderName)
	}
	// the real URI of the request is set in 'x-client-uri'
	clientURI := r.Header.Get(URIHeaderName)
	if clientURI == "" {
		return ParsedRequest{}, fmt.Errorf("missing '%s' header", URIHeaderName)
	}
	// the real VERB of the request is set in 'x-client-uri'
	clientMethod := r.Header.Get(VerbHeaderName)
	if clientMethod == "" {
		return ParsedRequest{}, fmt.Errorf("missing '%s' header", VerbHeaderName)
	}

	// delete those headers before coraza process the request
	delete(r.Header, IPHeaderName)
	delete(r.Header, HostHeaderName)
	delete(r.Header, URIHeaderName)
	delete(r.Header, VerbHeaderName)

	parsedURL, err := url.Parse(clientURI)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("unable to parse url '%s': %s", clientURI, err)
	}

	remoteAddrNormalized := ""
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Errorf("Invalid appsec remote IP source %v: %s", r.RemoteAddr, err.Error())
		remoteAddrNormalized = r.RemoteAddr
	} else {
		ip := net.ParseIP(host)
		if ip == nil {
			log.Errorf("Invalid appsec remote IP address source %v: %s", r.RemoteAddr, err.Error())
			remoteAddrNormalized = r.RemoteAddr
		} else {
			remoteAddrNormalized = ip.String()
		}
	}

	return ParsedRequest{
		RemoteAddr:           r.RemoteAddr,
		UUID:                 uuid.New().String(),
		ClientHost:           clientHost,
		ClientIP:             clientIP,
		URI:                  parsedURL.Path,
		Method:               clientMethod,
		Host:                 r.Host,
		Headers:              r.Header,
		URL:                  r.URL,
		Proto:                r.Proto,
		Body:                 body,
		Args:                 parsedURL.Query(), //TODO: Check if there's not potential bypass as it excludes malformed args
		TransferEncoding:     r.TransferEncoding,
		ResponseChannel:      make(chan AppsecTempResponse),
		RemoteAddrNormalized: remoteAddrNormalized,
	}, nil
}
