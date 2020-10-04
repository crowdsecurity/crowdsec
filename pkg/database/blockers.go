package database

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/blocker"
	"github.com/pkg/errors"
)

func (c *Client) SelectBlocker(apiKey string) (*ent.Blocker, error) {
	result, err := c.Ent.Blocker.Query().Where(blocker.APIKeyEQ(apiKey)).First(c.CTX)
	if err != nil {
		return &ent.Blocker{}, errors.Wrap(QueryFail, "can't get last blocker pull")
	}

	return result, nil
}

func (c *Client) ListBlockers() ([]*ent.Blocker, error) {
	result, err := c.Ent.Blocker.Query().All(c.CTX)
	if err != nil {
		return []*ent.Blocker{}, errors.Wrap(QueryFail, "can't get last blocker pull")
	}
	return result, nil
}

func (c *Client) CreateBlocker(name string, ipAddr string, apiKey string) error {
	_, err := c.Ent.Blocker.
		Create().
		SetName(name).
		SetAPIKey(apiKey).
		SetRevoked(false).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to save api key in database: %s", err)
	}
	return nil
}

func (c *Client) DeleteBlocker(name string) error {
	_, err := c.Ent.Blocker.
		Delete().
		Where(blocker.NameEQ(name)).
		Exec(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to save api key in database: %s", err)
	}
	return nil
}

func (c *Client) UpdateBlockerLastPull(lastPull time.Time, ID int) error {
	_, err := c.Ent.Blocker.UpdateOneID(ID).
		SetLastPull(lastPull).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update machine in database: %s", err)
	}
	return nil
}
