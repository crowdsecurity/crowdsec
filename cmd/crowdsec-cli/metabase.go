package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/dghubble/sling"
	"github.com/pkg/errors"
	"github.com/prometheus/common/log"
)

const (
	mbDefaultEmail = "metabase@crowdsec.net"

	createDashboard    = "create_dashboard"
	addCardToDashboard = "add_card_to_dashboard"
	addDataSource      = "add_data_source"
	resetPassword      = "reset_password"
	session            = "session"
	setup              = "setup"
)

var (
	apiDef = map[string]*apiMethod{
		createDashboard: {
			Method: "POST",
			URI:    "/api/dashboard",
		},
		addCardToDashboard: {
			Method: "POST",
			URI:    "/api/dashboard/%s/cards",
		},
		addDataSource: {
			Method: "POST",
			URI:    "/api/database",
		},
		resetPassword: {
			Method: "POST",
			URI:    "user/1/password",
		},
		session: {
			Method: "POST",
			URI:    "/api/session",
		},
		setup: {
			Method: "POST",
			URI:    "/api/setup",
		},
	}
)

type metabase struct {
	dashboards []*dashboard
	config     *mbConfig
	httpCTX    *sling.Sling
}

type mbConfig struct {
	database   *csconfig.DatabaseCfg
	mbURL      string
	mbUsername string
	mbPassword string
}

type dashboard struct {
	Name string
}

type apiMethod struct {
	Action string
	Method string
	URI    string
	Params map[string]interface{}
}

func newMetabase(dbConfig *csconfig.DatabaseCfg, mbURL string, mbUsername string, mbPassword string) (*metabase, error) {
	httpClient := &http.Client{Timeout: 20 * time.Second}

	mb := &metabase{
		config: &mbConfig{
			database:   dbConfig,
			mbURL:      mbURL,
			mbUsername: mbUsername,
			mbPassword: mbPassword,
		},
		httpCTX: sling.New().Client(httpClient).Base(mbURL).Set("User-Agent", fmt.Sprintf("crowdsec/%s", cwversion.VersionStr())),
	}
	return mb, nil
}

func (m *metabase) init() error {
	// create datasource
	if err := m.Setup(); err != nil {
		return err
	}

	if err := m.WaitAlive(); err != nil {
		return err
	}

	return nil
}

func (m *metabase) Setup() error {
	return nil
}

func (m *metabase) WaitAlive() error {
	var resp *http.Response
	var err error
	log.Printf("waiting for metabase to be up")
	for {
		if resp, err = m.Auth(); err == nil {
			break
		}
		fmt.Printf(".")
		log.Debugf("waiting for metabase API to be up")
		time.Sleep(1 * time.Second)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "api session: fail to unmarshall body (status code %d)", resp.StatusCode)
		}
		return fmt.Errorf("api session: server return code %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (m *metabase) Auth() (*http.Response, error) {
	var respJSON interface{}
	requestBody, err := json.Marshal(map[string]string{"username": m.config.mbUsername, "password": m.config.mbPassword})
	if err != nil {
		return nil, err
	}
	return m.httpCTX.New().Post(apiDef[resetPassword].URI).BodyJSON(requestBody).Receive(respJSON, respJSON)

}

func (m *metabase) resetPassword(newPassword string) error {
	var respJSON interface{}
	requestBody, err := json.Marshal(map[string]string{
		"id":           "1",
		"password":     newPassword,
		"old_password": m.config.mbPassword})
	if err != nil {
		return err
	}

	resp, err := m.httpCTX.New().Post(apiDef[resetPassword].URI).BodyJSON(requestBody).Receive(respJSON, respJSON)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "reset password: fail to unmarshall body (status code %d)", resp.StatusCode)
		}
		return fmt.Errorf("reset password: server return code %d: %s", resp.StatusCode, body)
	}

	return nil
}
