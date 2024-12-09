package database

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/require"
)

func getDBClient(t *testing.T, ctx context.Context) *Client {
	t.Helper()

	dbPath, err := os.CreateTemp("", "*sqlite")
	require.NoError(t, err)
	dbClient, err := NewClient(ctx, &csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: dbPath.Name(),
	})
	require.NoError(t, err)

	return dbClient
}

func TestCheckAllowlist(t *testing.T) {

	ctx := context.Background()
	dbClient := getDBClient(t, ctx)

	allowlist, err := dbClient.CreateAllowList(ctx, "test", "test", false)

	require.NoError(t, err)

	err = dbClient.AddToAllowlist(ctx, allowlist, []*models.AllowlistItem{
		{
			CreatedAt: strfmt.DateTime(time.Now()),
			Value:     "1.2.3.4",
		},
		{
			CreatedAt: strfmt.DateTime(time.Now()),
			Value:     "8.0.0.0/8",
		},
		{
			CreatedAt: strfmt.DateTime(time.Now()),
			Value:     "2001:db8::/32",
		},
		{
			CreatedAt:  strfmt.DateTime(time.Now()),
			Value:      "2.3.4.5",
			Expiration: strfmt.DateTime(time.Now().Add(-time.Hour)), // expired item
		},
		{
			CreatedAt: strfmt.DateTime(time.Now()),
			Value:     "8a95:c186:9f96:4c75:0dad:49c6:ff62:94b8",
		},
	})

	require.NoError(t, err)

	// Exatch match
	allowlisted, err := dbClient.IsAllowlisted(ctx, "1.2.3.4")
	require.NoError(t, err)
	require.True(t, allowlisted)

	// CIDR match
	allowlisted, err = dbClient.IsAllowlisted(ctx, "8.8.8.8")
	require.NoError(t, err)
	require.True(t, allowlisted)

	// IPv6 match
	allowlisted, err = dbClient.IsAllowlisted(ctx, "2001:db8::1")
	require.NoError(t, err)
	require.True(t, allowlisted)

	// Expired item
	allowlisted, err = dbClient.IsAllowlisted(ctx, "2.3.4.5")
	require.NoError(t, err)
	require.False(t, allowlisted)

	// Decision on a range that contains an allowlisted value
	allowlisted, err = dbClient.IsAllowlisted(ctx, "1.2.3.0/24")
	require.NoError(t, err)
	require.True(t, allowlisted)

	// No match
	allowlisted, err = dbClient.IsAllowlisted(ctx, "42.42.42.42")
	require.NoError(t, err)
	require.False(t, allowlisted)

	// IPv6 range that contains an allowlisted value
	allowlisted, err = dbClient.IsAllowlisted(ctx, "8a95:c186:9f96:4c75::/64")
	require.NoError(t, err)
	require.True(t, allowlisted)
}