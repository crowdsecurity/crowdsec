package database

import (
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
)

func (c *Client) SelectBouncer(apiKeyHash string) (*ent.Bouncer, error) {
	result, err := c.Ent.Bouncer.Query().Where(bouncer.APIKeyEQ(apiKeyHash)).First(c.CTX)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) SelectBouncerByName(bouncerName string) (*ent.Bouncer, error) {
	result, err := c.Ent.Bouncer.Query().Where(bouncer.NameEQ(bouncerName)).First(c.CTX)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) ListBouncers() ([]*ent.Bouncer, error) {
	result, err := c.Ent.Bouncer.Query().All(c.CTX)
	if err != nil {
		return nil, errors.Wrapf(QueryFail, "listing bouncers: %s", err)
	}
	return result, nil
}

func (c *Client) CreateBouncer(name string, ipAddr string, apiKey string, authType string) (*ent.Bouncer, error) {
	bouncer, err := c.Ent.Bouncer.
		Create().
		SetName(name).
		SetAPIKey(apiKey).
		SetRevoked(false).
		SetAuthType(authType).
		Save(c.CTX)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, fmt.Errorf("bouncer %s already exists", name)
		}
		return nil, fmt.Errorf("unable to create bouncer: %s", err)
	}
	return bouncer, nil
}

func (c *Client) DeleteBouncer(name string) error {
	nbDeleted, err := c.Ent.Bouncer.
		Delete().
		Where(bouncer.NameEQ(name)).
		Exec(c.CTX)
	if err != nil {
		return err
	}

	if nbDeleted == 0 {
		return fmt.Errorf("bouncer doesn't exist")
	}

	return nil
}

func (c *Client) BulkDeleteBouncers(bouncers []*ent.Bouncer) (int, error) {
	ids := make([]int, len(bouncers))
	for i, b := range bouncers {
		ids[i] = b.ID
	}
	nbDeleted, err := c.Ent.Bouncer.Delete().Where(bouncer.IDIn(ids...)).Exec(c.CTX)
	if err != nil {
		return nbDeleted, fmt.Errorf("unable to delete bouncers: %s", err)
	}
	return nbDeleted, nil
}

func (c *Client) UpdateBouncerLastPull(lastPull time.Time, ID int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(ID).
		SetLastPull(lastPull).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update machine last pull in database: %s", err)
	}
	return nil
}

func (c *Client) UpdateBouncerIP(ipAddr string, ID int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(ID).SetIPAddress(ipAddr).Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update bouncer ip address in database: %s", err)
	}
	return nil
}

func (c *Client) UpdateBouncerTypeAndVersion(bType string, version string, ID int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(ID).SetVersion(version).SetType(bType).Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update bouncer type and version in database: %s", err)
	}
	return nil
}

func (c *Client) QueryBouncersLastPulltimeLT(t time.Time) ([]*ent.Bouncer, error) {
	return c.Ent.Bouncer.Query().Where(bouncer.LastPullLT(t)).All(c.CTX)
}
