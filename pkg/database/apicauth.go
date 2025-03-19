package database

import (
	"context"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/apicauth"
)

func (c *Client) UpsertApicAuth(ctx context.Context, token string, expiration time.Time) (*ent.ApicAuth, error) {
	// Query by the unique singleton field.
	auth, err := c.Ent.ApicAuth.
		Query().
		Where(apicauth.SingletonEQ("only")).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// No record exists, so create one.
			return c.Ent.ApicAuth.
				Create().
				SetToken(token).
				SetExpiration(expiration).
				SetSingleton("only").
				Save(ctx)
		}
		return nil, err
	}
	// Record exists; update it.
	return c.Ent.ApicAuth.
		UpdateOne(auth).
		SetToken(token).
		SetExpiration(expiration).
		Save(ctx)
}

func (c *Client) GetApicAuth(ctx context.Context) (string, time.Time, error) {
	auth, err := c.Ent.ApicAuth.
		Query().
		Where(apicauth.SingletonEQ("only")).
		Only(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	return auth.Token, auth.Expiration, nil
}
