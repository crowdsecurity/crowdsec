package metabase

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
)

type MBClient struct {
	CTX    *sling.Sling
	Client *http.Client
}

const (
	sessionEndpoint       = "login"
	scanEndpoint          = "scan"
	resetPasswordEndpoint = "reset_password"
	userEndpoint          = "user"
	databaseEndpoint      = "database"
)

var (
	routes = map[string]string{
		sessionEndpoint:       "api/session",
		scanEndpoint:          "api/database/2/rescan_values",
		resetPasswordEndpoint: "api/user/1/password",
		userEndpoint:          "api/user/1",
		databaseEndpoint:      "api/database/2",
	}
)

func NewMBClient(url string) (*MBClient, error) {
	httpClient := &http.Client{Timeout: 20 * time.Second}
	return &MBClient{
		CTX:    sling.New().Client(httpClient).Base(url).Set("User-Agent", fmt.Sprintf("crowdsec/%s", version.String())),
		Client: httpClient,
	}, nil
}

func (h *MBClient) Do(method string, route string, body interface{}) (interface{}, interface{}, error) {
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
		return Success, Error, fmt.Errorf("bad status code '%d': (success: %+v) | (error: %+v)", resp.StatusCode, Success, Error)
	}
	return Success, Error, err
}

// Set headers as key:value
func (h *MBClient) Set(key string, value string) {
	h.CTX = h.CTX.Set(key, value)
}
