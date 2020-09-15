package database

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	Ent *ent.Client
	CTX context.Context
}

func NewClient(config *csconfig.DatabaseConfig) (*Client, error) {
	/*var client *ent.Client
	var err error
	switch config.Type {
	case "sqlite":
		client, err = ent.Open("sqlite3", fmt.Sprintf("file:%s?_busy_timeout=100000&_fk=1", config.Path))
		if err != nil {
			return &Client{}, fmt.Errorf("failed opening connection to sqlite: %v", err)
		}
	case "mysql":
		client, err = ent.Open("mysql", "root:crowdsec@tcp(172.16.0.2:3306)/crowdsec?parseTime=True")
		if err != nil {
			return &Client{}, fmt.Errorf("failed opening connection to mysql: %v", err)
		}
	default:
		return &Client{}, fmt.Errorf("unknown database type")
	}*/

	client, err := ent.Open("mysql", "root:crowdsec@tcp(172.16.0.2:3306)/crowdsec?parseTime=True")
	if err != nil {
		return &Client{}, fmt.Errorf("failed opening connection to mysql: %v", err)
	}
	log.Printf("Creating schema")
	if err = client.Debug().Schema.Create(context.Background()); err != nil {
		return nil, fmt.Errorf("failed creating schema resources: %v", err)
	}
	log.Printf("Schema created!!")
	return &Client{Ent: client, CTX: context.Background()}, nil
}

func (c *Client) IsMachineRegister(machineID string) (bool, error) {
	exist, err := c.Ent.Machine.Query().Where().Select(machine.FieldMachineId).Strings(c.CTX)
	if err != nil {
		return false, err
	}
	if len(exist) > 0 {
		return true, nil
	}

	return false, nil

}
