package metabase

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/pkg/errors"
)

type Databases struct {
	db map[int]*Database
}

type Database struct {
	ID     int
	Model  *DatabaseModel
	Config *csconfig.DatabaseCfg
	Client *HTTP
}

type DatabaseModel struct {
	Engine         string                    `json:"engine"`
	Name           string                    `json:"name"`
	Details        *DetailsModel             `json:"details"`
	AutoRunQueries bool                      `json:"auto_run_queries"`
	IsFullSync     bool                      `json:"is_full_sync"`
	Schedules      map[string]*ScheduleModel `json:"schedules"`
}

type DetailsModel struct {
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

type ScheduleModel struct {
	ScheduleDay   interface{} `json:"schedule_day"`
	ScheduleFrame interface{} `json:"schedule_frame"`
	ScheduleHour  int         `json:"schedule_hour"`
	ScheduleType  string      `json:"hourly"`
}

func NewDatabase(config *Config, client *HTTP) (*Database, error) {
	var database *DatabaseModel
	switch config.Database.Type {
	case "sqlite":
		database = &DatabaseModel{
			Engine: config.Database.Type,
			Name:   "crowdsec",
			Details: &DetailsModel{
				DB:                        "/metabase-data/crowdsec.db",
				LetUserControleScheduling: true,
			},
			AutoRunQueries: true,
		}
	case "mysql":
		database = &DatabaseModel{
			Engine: config.Database.Type,
			Name:   config.Database.DbName,
			Details: &DetailsModel{
				Host:          config.Database.Host,
				Port:          config.Database.Port,
				DBName:        config.Database.DbName,
				User:          config.Database.User,
				Password:      config.Database.Password,
				SSL:           false,
				TunnelEnabled: false,
			},
			AutoRunQueries: false,
			IsFullSync:     true,
			Schedules: map[string]*ScheduleModel{
				"cache_field_values": {
					ScheduleHour: 0,
					ScheduleType: "hourly",
				},
				"metadata_sync": {
					ScheduleType: "hourly",
				},
			},
		}
	default:
		return nil, fmt.Errorf("unsupported database type '%s'", config.Database.Type)
	}

	return &Database{
		Model:  database,
		Config: config.Database,
		Client: client,
	}, nil

}

func (d *Database) Add() error {
	success, errormsg, err := d.Client.Do("POST", routes[databaseEndpoint], d.Model)
	if err != nil {
		return errors.Wrap(err, "add database:")
	}
	if errormsg != nil {
		return fmt.Errorf("add database: %+v", errormsg)
	}

	body, ok := success.(map[string]interface{})
	if !ok {
		return fmt.Errorf("bad response type: %+v", success)
	}
	if _, ok := body["id"]; !ok {
		return fmt.Errorf("no database id, no id in response: %v", body)
	}

	idFloat, ok := body["id"].(float64)
	if !ok {
		return fmt.Errorf("bad database id type: %v", body)
	}
	d.ID = int(idFloat)

	return nil
}
