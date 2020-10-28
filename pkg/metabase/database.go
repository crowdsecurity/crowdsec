package metabase

import (
	"encoding/json"
	"net/http"
	"os"
)

type Database struct {
	ID    int
	Name  string
	Path  string
	Model *DatabaseModel
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

func (m *Metabase) AddDatabase() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}

	var database *DatabaseModel
	switch m.Config.database.Type {
	case "sqlite":
		database = &DatabaseModel{
			Engine: m.Config.database.Type,
			Name:   "crowdsec",
			Details: &DetailsModel{
				DB:                        "/metabase-data/crowdsec.db",
				LetUserControleScheduling: true,
			},
			AutoRunQueries: true,
		}
	case "mysql":
		database = &DatabaseModel{
			Engine: m.Config.database.Type,
			Name:   m.Config.database.DbName,
			Details: &DetailsModel{
				Host:          m.Config.database.Host,
				Port:          m.Config.database.Port,
				DBName:        m.Config.database.DbName,
				User:          m.Config.database.User,
				Password:      m.Config.database.Password,
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

	}
	resp, err := m.Client.New().Post(routes[databaseEndpoint]).BodyJSON(database).Receive(&respJSON, &respJSON)

	if err != nil {
		return nil, nil, err
	}

	db := &Database{
		ID:    int(respJSON["id"].(float64)),
		Name:  respJSON["name"].(string),
		Model: database,
	}
	m.Databases = append(m.Databases, db)

	return respJSON, resp, nil
}

func (d *Database) Backup(data map[string]interface{}) error {
	f, err := os.Create(d.Path)

	if err != nil {
		return err
	}

	defer f.Close()

	dataStr, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = f.WriteString(string(dataStr))
	if err != nil {
		return err
	}
	return nil
}
