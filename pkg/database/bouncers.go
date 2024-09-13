package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type BouncerNotFoundError struct {
	BouncerName string
}

func (e *BouncerNotFoundError) Error() string {
	return fmt.Sprintf("'%s' does not exist", e.BouncerName)
}

func (c *Client) BouncerUpdateBaseMetrics(ctx context.Context, bouncerName string, bouncerType string, baseMetrics models.BaseMetrics) error {
	os := baseMetrics.Os
	features := strings.Join(baseMetrics.FeatureFlags, ",")

	_, err := c.Ent.Bouncer.
		Update().
		Where(bouncer.NameEQ(bouncerName)).
		SetNillableVersion(baseMetrics.Version).
		SetOsname(*os.Name).
		SetOsversion(*os.Version).
		SetFeatureflags(features).
		SetType(bouncerType).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update base bouncer metrics in database: %w", err)
	}

	return nil
}

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

func (c *Client) ListBouncers(ctx context.Context) ([]*ent.Bouncer, error) {
	result, err := c.Ent.Bouncer.Query().All(ctx)
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

		return nil, fmt.Errorf("unable to create bouncer: %w", err)
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
		return &BouncerNotFoundError{BouncerName: name}
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
		return nbDeleted, fmt.Errorf("unable to delete bouncers: %w", err)
	}

	return nbDeleted, nil
}

func (c *Client) UpdateBouncerLastPull(lastPull time.Time, id int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(id).
		SetLastPull(lastPull).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update machine last pull in database: %w", err)
	}

	return nil
}

func (c *Client) UpdateBouncerIP(ipAddr string, id int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(id).SetIPAddress(ipAddr).Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update bouncer ip address in database: %w", err)
	}

	return nil
}

func (c *Client) UpdateBouncerTypeAndVersion(bType string, version string, id int) error {
	_, err := c.Ent.Bouncer.UpdateOneID(id).SetVersion(version).SetType(bType).Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update bouncer type and version in database: %w", err)
	}

	return nil
}

func (c *Client) QueryBouncersInactiveSince(t time.Time) ([]*ent.Bouncer, error) {
	return c.Ent.Bouncer.Query().Where(
		// poor man's coalesce
		bouncer.Or(
			bouncer.LastPullLT(t),
			bouncer.And(
				bouncer.LastPullIsNil(),
				bouncer.CreatedAtLT(t),
			),
		),
	).All(c.CTX)
}
