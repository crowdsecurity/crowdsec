package database

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/configitem"
)

func (c *Client) GetConfigItem(ctx context.Context, key string) (string, error) {
	result, err := c.Ent.ConfigItem.Query().Where(configitem.NameEQ(key)).First(ctx)

	switch {
	case ent.IsNotFound(err):
		return "", nil
	case err != nil:
		return "", errors.Wrapf(QueryFail, "select config item: %s", err)
	default:
		return result.Value, nil
	}
}

func (c *Client) SetConfigItem(ctx context.Context, key string, value string) error {
	nbUpdated, err := c.Ent.ConfigItem.Update().SetValue(value).Where(configitem.NameEQ(key)).Save(ctx)

	switch {
	case ent.IsNotFound(err) || nbUpdated == 0:
		// not found, create
		err := c.Ent.ConfigItem.Create().SetName(key).SetValue(value).Exec(ctx)
		if err != nil {
			return errors.Wrapf(QueryFail, "insert config item: %s", err)
		}
	case err != nil:
		return errors.Wrapf(QueryFail, "update config item: %s", err)
	}

	return nil
}

// LoadAPICToken attempts to retrieve and validate a JWT token from the local database.
// It returns the token string, its expiration time, and a boolean indicating whether the token is valid.
//
// A token is considered valid if:
//   - it exists in the database,
//   - it is a properly formatted JWT with an "exp" claim,
//   - it is not expired or near expiry.
func (c *Client) LoadAPICToken(ctx context.Context, logger logrus.FieldLogger) (string, time.Time, bool) {
	token, err := c.GetConfigItem(ctx, apiclient.TokenDBField) // TokenKey is a constant string representing the key for the token in the database
	if err != nil {
		logger.Debugf("error fetching token from DB: %s", err)
		return "", time.Time{}, false
	}

	if token == "" {
		logger.Debug("no token found in DB")
		return "", time.Time{}, false
	}

	parser := new(jwt.Parser)

	tok, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		logger.Debugf("error parsing token: %s", err)
		return "", time.Time{}, false
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		logger.Debugf("error parsing token claims: %s", err)
		return "", time.Time{}, false
	}

	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		logger.Debug("token missing 'iat' claim")
		return "", time.Time{}, false
	}

	iat := time.Unix(int64(iatFloat), 0)
	if time.Now().UTC().After(iat.Add(1 * time.Minute)) {
		logger.Debug("token is more than 1 minute old, not using it")
		return "", time.Time{}, false
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		logger.Debug("token missing 'exp' claim")
		return "", time.Time{}, false
	}

	exp := time.Unix(int64(expFloat), 0)
	if time.Now().UTC().After(exp.Add(-1 * time.Minute)) {
		logger.Debug("auth token expired")
		return "", time.Time{}, false
	}

	return token, exp, true
}

// SaveAPICToken stores the given JWT token in the local database under the appropriate config item.
func (c *Client) SaveAPICToken(ctx context.Context, tokenKey string, token string) error {
	if err := c.SetConfigItem(ctx, tokenKey, token); err != nil {
		return fmt.Errorf("saving token to db: %w", err)
	}

	return nil
}
