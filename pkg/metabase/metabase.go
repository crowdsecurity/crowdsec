package metabase

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
)

const (
	dashboardFile  = "dashboards.json"
	credentialFile = "credentials.yaml"
)

type mbConfig struct {
	database   *csconfig.DatabaseCfg
	mbURL      string
	mbUsername string
	mbPassword string
	setupToken string
	mbFolder   string
	UserID     int
}

type Metabase struct {
	Dashboards []*Dashboard
	Databases  []*Database
	Config     *mbConfig
	Client     *sling.Sling
	User       *Creator
}

func NewMetabase(dbConfig *csconfig.DatabaseCfg, mbURL string, mbUsername string, mbPassword string, metabaseFolder string) (*Metabase, error) {
	mb := &Metabase{
		Config: &mbConfig{
			database:   dbConfig,
			mbURL:      mbURL,
			mbUsername: mbUsername,
			mbPassword: mbPassword,
			mbFolder:   metabaseFolder,
		},
	}
	return mb, nil
}

func (m *Metabase) Init() error {
	httpClient := &http.Client{Timeout: 20 * time.Second}
	m.Client = sling.New().Client(httpClient).Base(m.Config.mbURL).Set("User-Agent", fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()))
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

	// setup metabase
	if _, _, err := m.FirstSetup(); err != nil {
		return err
	}

	m.User, _, err = m.CurrentUser()
	if err != nil {
		return err
	}

	if _, _, err := m.AddDatabase(); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)

	if err := m.Import(archive); err != nil {
		return err
	}

	return nil
}

func (m *Metabase) CurrentUser() (*Creator, *http.Response, error) {
	user := Creator{}
	resp, err := m.Client.New().Get(routes[currentUser]).Receive(&user, &user)
	if err != nil {
		return nil, nil, err
	}
	return &user, resp, nil
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
		if _, _, err := dashboard.AddDashboard(); err != nil {
			log.Errorf("fail to created dashboard '%s': %s", dashboard.Name, err)
			continue
		}
		log.Infof("dashboard : %+v \n", dashboard)
		if _, err := os.Stat(filepath.Join(dashboard.Folder, "dashboard.json")); os.IsNotExist(err) {
			log.Errorf("can't find '%s', skip", filepath.Join(dashboard.Folder, "dashboardjson"))
			continue
		}

		file, err := ioutil.ReadFile(filepath.Join(dashboard.Folder, "dashboard.json"))
		if err != nil {
			return err
		}

		if err := json.Unmarshal(file, &dashboard.Data); err != nil {
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
		for _, file := range files {

			card, err := NewCard(file, dashboard.ID, m.Client, m.User)
			if err != nil {
				log.Errorf("unable to create card: %s", err)
				continue
			}
			if _, _, err := card.AddCard(); err != nil {
				log.Errorf("error while adding card '%s' : %s", file, err)
				continue
			}
			log.Infof("Adding card from '%s'", file)

			if _, _, err := card.AddCardToDashboard(); err != nil {
				log.Errorf("error while adding card to dashboard '%s' : %s", file, err)
				continue
			}
			dashboard.Cards = append(dashboard.Cards, card)
		}

		log.Infof("updating dashboard '%s'", dashboard.Name)
		if _, _, err := dashboard.Update(); err != nil {
			return err
		}
		m.Dashboards = append(m.Dashboards, dashboard)
	}

	os.RemoveAll("/tmp/crowdsec_metabase/")
	return nil
}

func (m *Metabase) Export(target string) error {
	dashboards, _, err := m.GetDashboards()
	if err != nil {
		return err
	}

	tmpFolder := "./crowdsec_metabase"
	log.Infof("creating temporary directory: %s", tmpFolder)

	for _, dashboard := range dashboards {
		dash := &Dashboard{
			ID:     int(int(dashboard["id"].(float64))),
			Name:   dashboard["name"].(string),
			Client: m.Client,
			Folder: filepath.Join(tmpFolder, "dashboards", dashboard["name"].(string)),
		}

		if err := os.MkdirAll(dash.Folder, os.ModePerm); err != nil {
			return err
		}
		log.Infof("backup dashboard '%s'", dash.Name)
		if err := dash.Backup(); err != nil {
			return err
		}

		m.Dashboards = append(m.Dashboards, dash)
	}

	dumpDashboards, err := json.Marshal(m.Dashboards)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(tmpFolder, "dashboards.json"), dumpDashboards, 0644)
	if err != nil {
		return err
	}

	databases, _, err := m.GetDatabases()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(tmpFolder, "databases"), os.ModePerm); err != nil {
		return err
	}
	for _, database := range databases {
		dbFilename := fmt.Sprintf("%s_%d.json", database["name"].(string), int(database["id"].(float64)))
		d := &Database{
			Path: filepath.Join(tmpFolder, "databases", dbFilename),
		}

		if err := d.Backup(database); err != nil {
			return err
		}
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

func (m *Metabase) GetDashboards() ([]map[string]interface{}, *http.Response, error) {
	var respJSON []map[string]interface{}

	resp, err := m.Client.New().Get(routes[dashboardEndpoint]).Receive(&respJSON, &respJSON)
	if err != nil {
		return nil, nil, err
	}

	return respJSON, resp, nil
}

func (m *Metabase) GetDatabases() ([]map[string]interface{}, *http.Response, error) {
	var respJSON []map[string]interface{}

	resp, err := m.Client.New().Get(routes[databaseEndpoint]).Receive(&respJSON, &respJSON)
	if err != nil {
		return nil, nil, err
	}

	return respJSON, resp, nil
}
