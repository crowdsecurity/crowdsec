package database

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/blocker"
	"github.com/pkg/errors"
)

func (c *Client) LastBlockerPull(apiKey string) (string, error) {
	result, err := c.Ent.Blocker.Query().Where(blocker.APIKeyEQ(apiKey)).Select(blocker.FieldLastPull).Strings(c.CTX)
	if err != nil {
		return "", errors.Wrap(QueryFail, "can't get last blocker pull")
	}

	return result[0], nil
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
