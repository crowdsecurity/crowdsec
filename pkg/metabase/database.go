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
	DBUrl       string
	SQLiteModel *SQLiteModel
	Config      *csconfig.DatabaseCfg
	Client      *APIClient
	Update      func() error
}

type SQLiteModel struct {
	Engine  string `json:"engine"`
	Name    string `json:"name"`
	Details struct {
		Db string `json:"db"`
	} `json:"details"`
	AutoRunQueries bool                   `json:"auto_run_queries"`
	IsFullSync     bool                   `json:"is_full_sync"`
	IsOnDemand     bool                   `json:"is_on_demand"`
	Schedules      map[string]interface{} `json:"schedules"`
}

func NewDatabase(config *csconfig.DatabaseCfg, client *APIClient) (*Database, error) {
	database := Database{}
	switch config.Type {
	case "mysql":
		database.DBUrl = metabaseMySQLDBURL
	case "sqlite":
		database.DBUrl = metabaseSQLiteDBURL
		database.Update = database.UpdateSQLiteDB
	case "postegresql", "postegres", "pgsql":
		database.DBUrl = metabasePgSQLDBURL
	default:
		return nil, fmt.Errorf("database '%s' not supported", config.Type)
	}

	database.Client = client
	database.Config = config

	return &database, nil
}

func (d *Database) UpdateSQLiteDB() error {
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

	model := SQLiteModel{}

	if err := json.Unmarshal(data, &model); err != nil {
		return errors.Wrap(err, "update sqlite db response (unmarshal)")
	}

	localFolder := filepath.Dir(d.Config.DbPath)
	dbPath := strings.Replace(d.Config.DbPath, localFolder, containerSharedFolder, 1)
	model.Details.Db = strings.Replace(d.Config.DbPath, localFolder, containerSharedFolder, 1)
	success, errormsg, err = d.Client.Do("PUT", routes[databaseEndpoint], model)
	if err != nil {
		return err
	}
	if errormsg != nil {
		return fmt.Errorf("update sqlite db http error: %+v", errormsg)
	}

	return nil
}
