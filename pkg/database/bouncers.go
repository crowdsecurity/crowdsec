package database

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
)

func (c *Client) SelectBouncer(ctx context.Context, apiKeyHash string) (*ent.Bouncer, error) {
	result, err := c.Ent.Bouncer.Query().Where(bouncer.APIKeyEQ(apiKeyHash)).First(ctx)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) SelectBouncerByName(ctx context.Context, bouncerName string) (*ent.Bouncer, error) {
	result, err := c.Ent.Bouncer.Query().Where(bouncer.NameEQ(bouncerName)).First(ctx)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) ListBouncers(ctx context.Context) ([]*ent.Bouncer, error) {
	result, err := c.Ent.Bouncer.Query().All(ctx)
	if err != nil {
		return nil, errors.Wrapf(QueryFail, "listing bouncers: %s", err)
	}

	return result, nil
}

func (c *Client) CreateBouncer(ctx context.Context, name string, ipAddr string, apiKey string, authType string) (*ent.Bouncer, error) {
	bouncer, err := c.Ent.Bouncer.
		Create().
		SetName(name).
		SetAPIKey(apiKey).
		SetRevoked(false).
		SetAuthType(authType).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, fmt.Errorf("bouncer %s already exists", name)
		}

		return nil, fmt.Errorf("unable to create bouncer: %w", err)
	}

	return bouncer, nil
}

func (c *Client) DeleteBouncer(ctx context.Context, name string) error {
	nbDeleted, err := c.Ent.Bouncer.
		Delete().
		Where(bouncer.NameEQ(name)).
		Exec(ctx)
	if err != nil {
		return err
	}

	if nbDeleted == 0 {
		return errors.New("bouncer doesn't exist")
	}

	return nil
}

func (c *Client) BulkDeleteBouncers(ctx context.Context, bouncers []*ent.Bouncer) (int, error) {
	ids := make([]int, len(bouncers))
	for i, b := range bouncers {
		ids[i] = b.ID
	}

	nbDeleted, err := c.Ent.Bouncer.Delete().Where(bouncer.IDIn(ids...)).Exec(ctx)
	if err != nil {
		return nbDeleted, fmt.Errorf("unable to delete bouncers: %w", err)
	}

	return nbDeleted, nil
}

func (c *Client) UpdateBouncerLastPull(ctx context.Context, lastPull time.Time, id int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(id).
		SetLastPull(lastPull).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update machine last pull in database: %w", err)
	}

	return nil
}

func (c *Client) UpdateBouncerIP(ctx context.Context, ipAddr string, id int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(id).SetIPAddress(ipAddr).Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update bouncer ip address in database: %w", err)
	}

	return nil
}

func (c *Client) UpdateBouncerTypeAndVersion(ctx context.Context, bType string, version string, id int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(id).SetVersion(version).SetType(bType).Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update bouncer type and version in database: %w", err)
	}

	return nil
}

func (c *Client) QueryBouncersLastPulltimeLT(ctx context.Context, t time.Time) ([]*ent.Bouncer, error) {
	return c.Ent.Bouncer.Query().Where(bouncer.LastPullLT(t)).All(ctx)
}
