package waf

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/corazawaf/coraza/v3/experimental"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/google/uuid"
)

type ResponseRequest struct {
	UUID         string
	Tx           corazatypes.Transaction
	Interruption *corazatypes.Interruption
	Err          error
	SendEvents   bool
}

func NewResponseRequest(Tx experimental.FullTransaction, in *corazatypes.Interruption, UUID string, err error) ResponseRequest {
	return ResponseRequest{
		UUID:         UUID,
		Tx:           Tx,
		Interruption: in,
		Err:          err,
		SendEvents:   true,
	}
}

func (r *ResponseRequest) SetRemediation(remediation string) error {
	r.Interruption.Action = remediation
	return nil
}

func (r *ResponseRequest) SetRemediationByID(ID int, remediation string) error {
	if r.Interruption.RuleID == ID {
		r.Interruption.Action = remediation
	}
	return nil
}

func (r *ResponseRequest) CancelEvent() error {
	// true by default
	r.SendEvents = false
	return nil
}

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
	ResponseChannel  chan ResponseRequest
}

func NewParsedRequestFromRequest(r *http.Request) (ParsedRequest, error) {
	var body []byte
	var err error

	if r.Body != nil {
		body = make([]byte, 0)
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return ParsedRequest{}, fmt.Errorf("unable to read body: %s", err)
		}
	}

	// the real source of the request is set in 'x-client-ip'
	clientIP := r.Header.Get("X-Client-Ip")
	// the real target Host of the request is set in 'x-client-host'
	clientHost := r.Header.Get("X-Client-Host")
	// the real URI of the request is set in 'x-client-uri'
	clientURI := r.Header.Get("X-Client-Uri")

	// delete those headers before coraza process the request
	delete(r.Header, "x-client-ip")
	delete(r.Header, "x-client-host")
	delete(r.Header, "x-client-uri")

	return ParsedRequest{
		RemoteAddr:       r.RemoteAddr,
		UUID:             uuid.New().String(),
		ClientHost:       clientHost,
		ClientIP:         clientIP,
		URI:              clientURI,
		Host:             r.Host,
		Headers:          r.Header,
		URL:              r.URL,
		Method:           r.Method,
		Proto:            r.Proto,
		Body:             body,
		TransferEncoding: r.TransferEncoding,
		ResponseChannel:  make(chan ResponseRequest),
	}, nil
}
