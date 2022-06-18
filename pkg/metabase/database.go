package metabase

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/pkg/errors"
)

type Database struct {
	DBUrl   string
	Model   *Model
	Config  *csconfig.DatabaseCfg
	Client  *APIClient
	Details *Details
	// in case mysql host is 127.0.0.1 the ip address of mysql/pgsql host will be the docker gateway since metabase run in a container
}

type Details struct {
	Db                string      `json:"db"`
	Host              string      `json:"host"`
	Port              int         `json:"port"`
	Dbname            string      `json:"dbname"`
	User              string      `json:"user"`
	Password          string      `json:"password"`
	Ssl               bool        `json:"ssl"`
	AdditionalOptions interface{} `json:"additional-options"`
	TunnelEnabled     bool        `json:"tunnel-enabled"`
}

type Model struct {
	Engine         string                 `json:"engine"`
	Name           string                 `json:"name"`
	Details        *Details               `json:"details"`
	AutoRunQueries bool                   `json:"auto_run_queries"`
	IsFullSync     bool                   `json:"is_full_sync"`
	IsOnDemand     bool                   `json:"is_on_demand"`
	Schedules      map[string]interface{} `json:"schedules"`
}

func NewDatabase(config *csconfig.DatabaseCfg, client *APIClient, remoteDBAddr string) (*Database, error) {
	var details *Details

	database := Database{}

	switch config.Type {
	case "mysql":
		return nil, fmt.Errorf("database '%s' is not supported yet", config.Type)
	case "sqlite":
		database.DBUrl = metabaseSQLiteDBURL
		localFolder := filepath.Dir(config.DbPath)
		// replace /var/lib/crowdsec/data/ with /metabase-data/
		dbPath := strings.Replace(config.DbPath, localFolder, containerSharedFolder, 1)
		details = &Details{
			Db: dbPath,
		}
	case "postgresql", "postgres", "pgsql":
		return nil, fmt.Errorf("database '%s' is not supported yet", config.Type)
	default:
		return nil, fmt.Errorf("database '%s' not supported", config.Type)
	}
	database.Details = details
	database.Client = client
	database.Config = config

	return &database, nil
}

func (d *Database) Update() error {
	success, errormsg, err := d.Client.Do("GET", routes[databaseEndpoint], nil)
	if err != nil {
		return err
	}
	if errormsg != nil {
		return fmt.Errorf("update sqlite db http error: %+v", errormsg)
	}

	data, err := json.Marshal(success)
	if err != nil {
		return errors.Wrap(err, "update sqlite db response (marshal)")
	}

	model := Model{}

	if err := json.Unmarshal(data, &model); err != nil {
		return errors.Wrap(err, "update sqlite db response (unmarshal)")
	}
	model.Details = d.Details
	_, errormsg, err = d.Client.Do("PUT", routes[databaseEndpoint], model)
	if err != nil {
		return err
	}
	if errormsg != nil {
		return fmt.Errorf("update sqlite db http error: %+v", errormsg)
	}

	return nil
}
