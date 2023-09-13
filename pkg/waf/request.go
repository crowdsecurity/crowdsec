package waf

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/crowdsecurity/coraza/v3/experimental"
	"github.com/google/uuid"
)

const (
	URIHeaderName  = "X-Crowdsec-Waf-Uri"
	VerbHeaderName = "X-Crowdsec-Waf-Verb"
	HostHeaderName = "X-Crowdsec-Waf-Host"
	IPHeaderName   = "X-Crowdsec-Waf-Ip"
)

// type ResponseRequest struct {
// 	UUID         string
// 	Tx           corazatypes.Transaction
// 	Interruption *corazatypes.Interruption
// 	Err          error
// 	SendEvents   bool
// }

// func NewResponseRequest(Tx experimental.FullTransaction, in *corazatypes.Interruption, UUID string, err error) ResponseRequest {
// 	return ResponseRequest{
// 		UUID:         UUID,
// 		Tx:           Tx,
// 		Interruption: in,
// 		Err:          err,
// 		SendEvents:   true,
// 	}
// }

// func (r *ResponseRequest) SetRemediation(remediation string) error {
// 	if r.Interruption == nil {
// 		return nil
// 	}
// 	r.Interruption.Action = remediation
// 	return nil
// }

// func (r *ResponseRequest) SetRemediationByID(ID int, remediation string) error {
// 	if r.Interruption == nil {
// 		return nil
// 	}
// 	if r.Interruption.RuleID == ID {
// 		r.Interruption.Action = remediation
// 	}
// 	return nil
// }

// func (r *ResponseRequest) CancelEvent() error {
// 	// true by default
// 	r.SendEvents = false
// 	return nil
// }

type ParsedRequest struct {
	RemoteAddr       string
	Host             string
	ClientIP         string
	URI              string
	ClientHost       string
	Headers          http.Header
	URL              *url.URL
	Method           string
	Proto            string
	Body             []byte
	TransferEncoding []string
	UUID             string
	Tx               experimental.FullTransaction
	ResponseChannel  chan WaapTempResponse
}

// Generate a ParsedRequest from a http.Request. ParsedRequest can be consumed by the Waap Engine
func NewParsedRequestFromRequest(r *http.Request) (ParsedRequest, error) {
	var err error
	body := make([]byte, 0)

	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return ParsedRequest{}, fmt.Errorf("unable to read body: %s", err)
		}
	}

	// the real source of the request is set in 'x-client-ip'
	clientIP := r.Header.Get(IPHeaderName)
	if clientIP == "" {
		return ParsedRequest{}, fmt.Errorf("Missing '%s' header", IPHeaderName)
	}
	// the real target Host of the request is set in 'x-client-host'
	clientHost := r.Header.Get(HostHeaderName)
	if clientHost == "" {
		return ParsedRequest{}, fmt.Errorf("Missing '%s' header", HostHeaderName)
	}
	// the real URI of the request is set in 'x-client-uri'
	clientURI := r.Header.Get(URIHeaderName)
	if clientURI == "" {
		return ParsedRequest{}, fmt.Errorf("Missing '%s' header", URIHeaderName)
	}
	// the real VERB of the request is set in 'x-client-uri'
	clientMethod := r.Header.Get(VerbHeaderName)
	if clientMethod == "" {
		return ParsedRequest{}, fmt.Errorf("Missing '%s' header", VerbHeaderName)
	}

	// delete those headers before coraza process the request
	delete(r.Header, IPHeaderName)
	delete(r.Header, HostHeaderName)
	delete(r.Header, URIHeaderName)
	delete(r.Header, VerbHeaderName)

	return ParsedRequest{
		RemoteAddr:       r.RemoteAddr,
		UUID:             uuid.New().String(),
		ClientHost:       clientHost,
		ClientIP:         clientIP,
		URI:              clientURI,
		Method:           clientMethod,
		Host:             r.Host,
		Headers:          r.Header,
		URL:              r.URL,
		Proto:            r.Proto,
		Body:             body,
		TransferEncoding: r.TransferEncoding,
		ResponseChannel:  make(chan WaapTempResponse),
	}, nil
}
