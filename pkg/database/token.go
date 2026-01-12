package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

const APICTokenKey = "apic_token"

var (
	ErrTokenNotFound     = errors.New("token not found in DB")
	ErrTokenParse        = errors.New("unable to parse token")
	ErrTokenMissingClaim = errors.New("token missing required claim")
	ErrTokenTooOld       = errors.New("token too old")
	ErrTokenExpired      = errors.New("token expired")
)

type APICToken struct {
	Raw       string
	ExpiresAt time.Time
}

// LoadAPICToken attempts to retrieve and validate a JWT token from the local database.
// Errors are returned if the token can't be read, is not valid, expired or has no expiration.
func (c *Client) LoadAPICToken(ctx context.Context, logger logrus.FieldLogger) (APICToken, error) {
	token, err := c.GetConfigItem(ctx, APICTokenKey) // TokenKey is a constant string representing the key for the token in the database
	if err != nil {
		return APICToken{}, fmt.Errorf("loading token: %w", err)
	}

	if token == "" {
		return APICToken{}, ErrTokenNotFound
	}

	parser := new(jwt.Parser)

	tok, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return APICToken{}, fmt.Errorf("%w: %s", ErrTokenParse, err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return APICToken{}, ErrTokenParse
	}

	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		return APICToken{}, fmt.Errorf("%w: iat", ErrTokenMissingClaim)
	}

	iat := time.Unix(int64(iatFloat), 0)
	if time.Now().UTC().After(iat.Add(1 * time.Minute)) {
		return APICToken{}, ErrTokenTooOld
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return APICToken{}, fmt.Errorf("%w: exp", ErrTokenMissingClaim)
	}

	exp := time.Unix(int64(expFloat), 0)
	if time.Now().UTC().After(exp.Add(-1 * time.Minute)) {
		return APICToken{}, ErrTokenExpired
	}

	return APICToken{Raw: token, ExpiresAt: exp}, nil
}

// SaveAPICToken stores the given JWT token in the local database under the appropriate config item.
func (c *Client) SaveAPICToken(ctx context.Context, token string) error {
	if err := c.SetConfigItem(ctx, APICTokenKey, token); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}

	return nil
}
