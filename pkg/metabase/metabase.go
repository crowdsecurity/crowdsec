package metabase

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	dashboardFile = "dashboards.json"
)

type Config struct {
	Database      *csconfig.DatabaseCfg
	URL           string `json:"url"`
	ListenPort    string `json:"listen_port"`
	ListenAddress string `json:"listen_address"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	setupToken    string
	Folder        string
}

type Metabase struct {
	Dashboards []*Dashboard
	Database   *Database
	Config     *Config
	Client     *HTTP
	User       *User
}

func NewMetabase(configPath string) (*Metabase, error) {
	m := &Metabase{}
	if err := m.LoadConfig(configPath); err != nil {
		return m, err
	}
	return m, nil
}

func (m *Metabase) Init() error {
	var err error
	m.Client, err = NewHTTP(m.Config)
	if err != nil {
		return err
	}

	return nil
}

func (m *Metabase) Setup(archive string) error {
	var err error
	if err := m.Init(); err != nil {
		return err
	}

	// wait Metabase to be alive
	if err := m.WaitAlive(); err != nil {
		return err
	}
	log.Debug("Metabase is alive")

	setup, err := NewSetup(m.Config, m.Client)
	if err != nil {
		return err
	}
	// setup metabase
	if err := setup.Run(); err != nil {
		return err
	}
	log.Debug("Metabse setup successfully")

	m.User, err = NewUser(m.Config, m.Client)
	if err != nil {
		return err
	}

	log.Debugf("User: %+v", m.User)

	m.Database, err = NewDatabase(m.Config, m.Client)
	if err != nil {
		return err
	}
	if err := m.Database.Add(); err != nil {
		return err
	}
	time.Sleep(1 * time.Second)

	log.Debugf("Database added successfully")

	if err := m.Import(archive); err != nil {
		return err
	}

	return nil

}

func (m *Metabase) LoadConfig(configPath string) error {
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	config := &Config{}

	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		return err
	}

	if config.Username == "" {
		return fmt.Errorf("'username' not found in credentials file '%s'", configPath)
	}

	if config.Password == "" {
		return fmt.Errorf("'password' not found in credentials file '%s'", configPath)
	}

	if config.URL == "" {
		return fmt.Errorf("'url' not found in credentials file '%s'", configPath)
	}

	if err := m.Init(); err != nil {
		return err
	}

	return nil

}

func (m *Metabase) GetSession() (interface{}, error) {
	success, errormsg, err := m.Client.Do("GET", routes[getSessionEndpoint], nil)
	if err != nil {
		return nil, err
	}

	if err != errormsg {
		return nil, fmt.Errorf("get session: %+v", errormsg)
	}
	return success, err
}

func (m *Metabase) WaitAlive() error {
	var err error
	var success interface{}
	for {
		if success, err = m.GetSession(); err == nil {
			break
		}
		fmt.Printf(".")
		time.Sleep(2 * time.Second)
	}
	fmt.Printf("\n")

	body, ok := success.(map[string]interface{})
	if !ok {
		return fmt.Errorf("get session: bad response type: %+v", success)
	}
	if _, ok := body["setup-token"]; !ok {
		return fmt.Errorf("no setup-token in response: %v", body)
	}
	token, ok := body["setup-token"].(string)
	if !ok {
		return fmt.Errorf("get session: setup token bad type: %+v", body)
	}
	m.Config.setupToken = token

	return nil
}

func (m *Metabase) Import(archive string) error {
	var dashboards []*Dashboard

	tmpFolder := "/tmp/"
	if err := Untar(archive, tmpFolder); err != nil {
		return err
	}

	tmpFolder = "/tmp/crowdsec_metabase/crowdsec_metabase"

	file, err := ioutil.ReadFile(filepath.Join(tmpFolder, dashboardFile))
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(file), &dashboards)
	if err != nil {
		return err
	}
	for _, dashboard := range dashboards {
		dashboard.Folder = filepath.Join(tmpFolder, "dashboards", dashboard.Name)
		if _, err := os.Stat(dashboard.Folder); os.IsNotExist(err) {
			log.Errorf("dashboard folder '%s' not found in '%s'")
			continue
		}
		dashboard.Client = m.Client

		log.Infof("creating dashboard from '%s'", dashboard.Folder)
		if err := dashboard.Add(); err != nil {
			log.Errorf("fail to created dashboard '%s': %s", dashboard.Name, err)
			continue
		}
		if _, err := os.Stat(filepath.Join(dashboard.Folder, "dashboard.json")); os.IsNotExist(err) {
			log.Errorf("can't find '%s', skip", filepath.Join(dashboard.Folder, "dashboardjson"))
			continue
		}

		file, err := ioutil.ReadFile(filepath.Join(dashboard.Folder, "dashboard.json"))
		if err != nil {
			return err
		}

		DashboardModel := GetDashboardModel{}

		if err := json.Unmarshal(file, &DashboardModel); err != nil {
			return err
		}

		dashboard.Model = &DashboardModel
		dashboard.Model.ID = dashboard.ID
		dashboard.SendModel = &UpdateDashboardModel{}
		get, _ := json.Marshal(dashboard.Model)
		if err := json.Unmarshal([]byte(get), dashboard.SendModel); err != nil {
			return err
		}
		// add cards from /etc/crowdsec/metabase/dashboards/<dashboard_name>/*.json
		var files []string

		err = filepath.Walk(filepath.Join(dashboard.Folder), func(path string, info os.FileInfo, err error) error {
			if filepath.Ext(path) == ".json" && filepath.Base(path) != "dashboard.json" {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return err
		}
		orderedCards := make([]*OrderedCard, 0)
		for _, file := range files {
			log.Debugf("creating card from '%s'", file)
			card, err := NewCardFromFile(file, dashboard.ID, m.Client, m.User)
			if err != nil {
				log.Errorf("unable to create card: %s", err)
				continue
			}

			if err := card.Dataset(); err != nil {
				return errors.Wrap(err, "card import:")
			}

			if err := card.Add(); err != nil {
				return errors.Wrap(err, "card import: ")
			}

			if err := card.Query(); err != nil {
				return errors.Wrap(err, "card import: ")
			}

			dashboard.Cards = append(dashboard.Cards, card)
			card.GetModel.Creator = m.User
			card.OrderedCard.CardID = card.GetModel.ID
			card.OrderedCard.Card.CanWrite = true
			dashboard.FrontInfo = append(dashboard.FrontInfo, card.AddFrontInfoModel)
			orderedCards = append(orderedCards, card.OrderedCard)
		}
		dashboard.SendModel.OrderedCards = orderedCards
		for _, card := range dashboard.Cards {
			if err := card.AddToDashboard(); err != nil {
				return errors.Wrap(err, "card import:")
			}
		}
		if err := dashboard.UpdateFrontInfo(); err != nil {
			return errors.Wrap(err, "update front:")
		}

		if err := dashboard.UpdateDashboard(m.User); err != nil {
			return errors.Wrap(err, "update dashboard")
		}

	}
	return nil
}

func (m *Metabase) GetDatabases() (interface{}, error) {
	success, errorMsg, err := m.Client.Do("GET", routes[databaseEndpoint], nil)
	if err != nil {
		return nil, err
	}

	if errorMsg != nil {
		return nil, fmt.Errorf("get database: %+v", errorMsg)
	}

	return success, nil
}

func (m *Metabase) Login() error {
	var err error

	if err := m.Init(); err != nil {
		return err
	}
	m.User, err = NewUser(m.Config, m.Client)
	if err != nil {
		return err
	}
	if _, err := m.User.Login(); err != nil {
		return err
	}
	return nil
}

func (m *Metabase) Export(target string) error {
	success, err := m.GetDashboards()
	if err != nil {
		return err
	}
	dash, err := json.Marshal(success)
	if err != nil {
		return errors.Wrap(err, "export: ")
	}
	dashboards := []*Dashboard{}
	if err := json.Unmarshal(dash, &dashboards); err != nil {
		return errors.Wrap(err, "export: ")
	}

	tmpFolder := "./crowdsec_metabase"
	log.Infof("creating temporary directory: %s", tmpFolder)

	for _, dashboard := range dashboards {

		dashboard.Folder = filepath.Join(tmpFolder, "dashboards", dashboard.Name)
		dashboard.Client = m.Client
		if err := os.MkdirAll(dashboard.Folder, os.ModePerm); err != nil {
			return err
		}
		log.Infof("backup dashboard '%s'", dashboard.Name)
		if err := dashboard.Backup(); err != nil {
			return err
		}

		m.Dashboards = append(m.Dashboards, dashboard)
	}

	dumpDashboards, err := json.Marshal(m.Dashboards)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(tmpFolder, "dashboards.json"), dumpDashboards, 0644)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(target, "/") {
		target = target + "/"
	}

	now := time.Now().Format("2006-01-02")
	target = fmt.Sprintf("%scrowdsec_metabase_%s", target, now)
	exclude := []string{"credentials.yaml"}
	if err := Tar(tmpFolder, target, exclude); err != nil {
		return err
	}

	os.RemoveAll("/tmp/crowdsec_metabase/")

	return nil
}

func (m *Metabase) GetDashboards() (interface{}, error) {
	success, errorMsg, err := m.Client.Do("GET", routes[dashboardEndpoint], nil)
	if err != nil {
		return nil, err
	}

	if errorMsg != nil {
		return nil, fmt.Errorf("get dashboards: %+v", errorMsg)
	}

	return success, nil
}

func (m *Metabase) DumpConfig(path string) error {
	data, err := json.Marshal(m.Config)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, 0600)
}
