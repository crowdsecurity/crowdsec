package metabase

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
)

type HTTP struct {
	CTX    *sling.Sling
	Client *http.Client
}

func NewHTTP(config *Config) (*HTTP, error) {
	httpClient := &http.Client{Timeout: 20 * time.Second}
	return &HTTP{
		CTX:    sling.New().Client(httpClient).Base(config.mbURL).Set("User-Agent", fmt.Sprintf("crowdsec/%s", cwversion.VersionStr())),
		Client: httpClient,
	}, nil
}

func (h *HTTP) Do(method string, route string, body interface{}) (interface{}, interface{}, error) {
	var Success interface{}
	var Error interface{}
	var resp *http.Response
	var err error
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}

	switch method {
	case "POST":
		log.Debugf("POST /%s", route)
		log.Debugf("%s", string(data))
		resp, err = h.CTX.New().Post(route).BodyJSON(body).Receive(&Success, &Error)
	case "GET":
		log.Debugf("GET /%s", route)
		resp, err = h.CTX.New().Get(route).Receive(&Success, &Error)
	case "PUT":
		log.Debugf("PUT /%s", route)
		log.Debugf("%s", string(data))
		resp, err = h.CTX.New().Put(route).BodyJSON(body).Receive(&Success, &Error)
	case "DELETE":
	default:
		return nil, nil, fmt.Errorf("unsupported method '%s'", method)
	}
	if Error != nil {
		return Success, Error, fmt.Errorf("http error: %v", Error)
	}

	if resp != nil && resp.StatusCode != 200 && resp.StatusCode != 202 {
		return Success, Error, fmt.Errorf("bad status code '%d': %v", resp.StatusCode, Success)
	}
	return Success, Error, err
}

func (h *HTTP) Set(key string, value string) {
	h.CTX = h.CTX.Set(key, value)
}
