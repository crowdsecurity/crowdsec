package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/dghubble/sling"
	"github.com/pkg/errors"
)

const (
	createDashboard    = "create_dashboard"
	addCardToDashboard = "add_card_to_dashboard"
	addDatabase        = "add_data_source"
	resetPassword      = "reset_password"
	login              = "login"
	setup              = "setup"
	getSession         = "get_session"
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
		addDatabase: {
			Method: "POST",
			URI:    "/api/database",
		},
		resetPassword: {
			Method: "POST",
			URI:    "user/1/password",
		},
		login: {
			Method: "POST",
			URI:    "/api/session",
		},
		setup: {
			Method: "POST",
			URI:    "/api/setup",
		},
		getSession: {
			Method: "GET",
			URI:    "/api/session/properties",
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
	setupToken string
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

func (m *metabase) Init() error {
	// wait Metabase to be alive
	if err := m.WaitAlive(); err != nil {
		return err
	}

	// setup metabase
	if _, _, err := m.Setup(); err != nil {
		return err
	}

	if _, _, err := m.AddDatabase(); err != nil {
		return err
	}

	if _, _, err := m.CreateDashboard(); err != nil {
		return err
	}
	return nil
}

func (m *metabase) Setup() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}
	type Prefs struct {
		SiteName      string `json:"site_name"`
		SiteLocal     string `json:"site_locale"`
		AllowTracking string `json:"allow_tracking"`
	}

	type User struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		SiteName  string `json:"site_name"`
	}

	data := struct {
		Token    string      `json:"token"`
		Prefs    *Prefs      `json:"prefs"`
		Database interface{} `json:"database"`
		User     *User       `json:"user"`
	}{
		Token: m.config.setupToken,
		Prefs: &Prefs{
			SiteName:      "crowdsec",
			SiteLocal:     "fr",
			AllowTracking: "false",
		},
		Database: nil,
		User: &User{
			FirstName: "crowdsec",
			LastName:  "crowdsec",
			Email:     "crowdsec@crowdsec.net",
			Password:  m.config.mbPassword,
			SiteName:  "crowdsec",
		},
	}

	resp, err := m.httpCTX.New().Post(apiDef[setup].URI).BodyJSON(data).Receive(&respJSON, &respJSON)
	m.httpCTX = m.httpCTX.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", respJSON["id"].(string)))

	log.Printf("Username: '%s'", m.config.mbUsername)
	log.Printf("Password: '%s'", m.config.mbPassword)

	return respJSON, resp, err

}

func (m *metabase) WaitAlive() error {
	var resp *http.Response
	var properties map[string]interface{}
	var err error
	for {
		if properties, resp, err = m.GetSession(); err == nil {
			break
		}
		fmt.Printf(".")
		time.Sleep(2 * time.Second)
	}
	fmt.Printf("\n")

	if resp.StatusCode != 200 {
		return fmt.Errorf("api session: server return code %d", resp.StatusCode)
	}
	m.config.setupToken = properties["setup-token"].(string)
	return nil
}

func (m *metabase) GetSession() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}
	resp, err := m.httpCTX.New().Get(apiDef[getSession].URI).Receive(&respJSON, &respJSON)
	return respJSON, resp, err
}

func (m *metabase) Auth() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}

	resp, err := m.httpCTX.New().Post(apiDef[login].URI).BodyJSON(map[string]string{
		"username": m.config.mbUsername,
		"password": m.config.mbPassword,
	}).Receive(&respJSON, &respJSON)

	m.httpCTX = m.httpCTX.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", respJSON["id"].(string)))

	return respJSON, resp, err

}

func (m *metabase) resetPassword(newPassword string) error {
	var respJSON map[string]interface{}
	resp, err := m.httpCTX.New().Post(apiDef[resetPassword].URI).BodyJSON(map[string]string{
		"id":           "1",
		"password":     newPassword,
		"old_password": m.config.mbPassword,
	}).Receive(&respJSON, &respJSON)
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

func (m *metabase) AddDatabase() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}

	type Details struct {
		DB                        string      `json:"db"`
		Host                      string      `json:"host"`
		Port                      int         `json:"port"`
		DBName                    string      `json:"dbname"`
		User                      string      `json:"user"`
		Password                  string      `json:"password"`
		SSL                       bool        `json:"ssl"`
		AdditionalOptions         interface{} `json:"additional-options"`
		TunnelEnabled             bool        `json:"tunnel_enabled"`
		LetUserControleScheduling bool        `json:"let-user-control-scheduling"`
	}

	type Schedule struct {
		ScheduleDay   interface{} `json:"schedule_day"`
		ScheduleFrame interface{} `json:"schedule_frame"`
		ScheduleHour  int         `json:"schedule_hour"`
		ScheduleType  string      `json:"hourly"`
	}

	type Database struct {
		Engine         string               `json:"engine"`
		Name           string               `json:"name"`
		Details        *Details             `json:"details"`
		AutoRunQueries bool                 `json:"auto_run_queries"`
		IsFullSync     bool                 `json:"is_full_sync"`
		Schedules      map[string]*Schedule `json:"schedules"`
	}

	var database *Database
	switch m.config.database.Type {
	case "sqlite":
		database = &Database{
			Engine: m.config.database.Type,
			Name:   "crowdsec",
			Details: &Details{
				DB:                        "/metabase-data/crowdsec.db",
				LetUserControleScheduling: true,
			},
			AutoRunQueries: true,
		}
	case "mysql":
		database = &Database{
			Engine: m.config.database.Type,
			Name:   m.config.database.DbName,
			Details: &Details{
				Host:          m.config.database.Host,
				Port:          m.config.database.Port,
				DBName:        m.config.database.DbName,
				User:          m.config.database.User,
				Password:      m.config.database.Password,
				SSL:           false,
				TunnelEnabled: false,
			},
			AutoRunQueries: false,
			IsFullSync:     true,
			Schedules: map[string]*Schedule{
				"cache_field_values": {
					ScheduleHour: 0,
					ScheduleType: "hourly",
				},
				"metadata_sync": {
					ScheduleType: "hourly",
				},
			},
		}

	}
	resp, err := m.httpCTX.New().Post(apiDef[addDatabase].URI).BodyJSON(database).Receive(&respJSON, &respJSON)
	return respJSON, resp, err
}

func (m *metabase) CreateDashboard() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}

	dashboard := map[string]string{
		"name":        "Mono-machine",
		"description": "Mono machine Crowdsec dashboard",
	}
	resp, err := m.httpCTX.New().Post(apiDef[createDashboard].URI).BodyJSON(dashboard).Receive(&respJSON, &respJSON)
	fmt.Printf("\n%v\n", respJSON)
	return respJSON, resp, err
}
