package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

const APICTokenKey = "apic_token"

// LoadAPICToken attempts to retrieve and validate a JWT token from the local database.
// It returns the token string (empty if the token was not valid) and its expiration time.
//
// A token is considered valid if:
//
// - it exists in the database,
// - it is a properly formatted JWT with an "exp" claim,
// - it is not expired or near expiry.
// - it matches the expected username.
//
// A bad token is deleted from the db before returning to the caller.
// This is more defensive than needed (we really only _have_ to remove it in case of user mismatch)
// but it prevents further invalid attempts.
func (c *Client) LoadAPICToken(ctx context.Context, expectedUser string, logger logrus.FieldLogger) (string, time.Time) {
	token, err := c.GetConfigItem(ctx, APICTokenKey)
	if err != nil {
		logger.Errorf("fetching token from DB: %s", err)
		return "", time.Time{}
	}

	invalid := func(format string, args ...any) (string, time.Time) {
		logger.Debugf(format, args...)

		if derr := c.DeleteConfigItem(ctx, APICTokenKey); derr != nil {
			logger.Errorf("deleting cached token from DB: %s", derr)
		}

		return "", time.Time{}
	}

	if token == "" {
		return "", time.Time{}
	}

	parser := new(jwt.Parser)

	tok, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return invalid("error parsing token: %s", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return invalid("error parsing token claims: %s", err)
	}

	sub, ok := claims["sub"].(string)
	if !ok || !strings.EqualFold(sub, expectedUser) {
		return invalid("token user mismatch: expected %s, got %v", expectedUser, sub)
	}

	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		return invalid("token missing 'iat' claim")
	}

	iat := time.Unix(int64(iatFloat), 0)
	if time.Now().UTC().After(iat.Add(1 * time.Minute)) {
		return invalid("token is more than 1 minute old, not using it")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return invalid("token missing 'exp' claim")
	}

	exp := time.Unix(int64(expFloat), 0)
	if time.Now().UTC().After(exp.Add(-1 * time.Minute)) {
		return invalid("auth token expired")
	}

	return token, exp
}

// SaveAPICToken stores the given JWT token in the local database under the appropriate config item.
func (c *Client) SaveAPICToken(ctx context.Context, token string) error {
	if err := c.SetConfigItem(ctx, APICTokenKey, token); err != nil {
		return fmt.Errorf("saving token to db: %w", err)
	}

	return nil
}
