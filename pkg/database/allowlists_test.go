package database

import (
	"context"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func getDBClient(t *testing.T, ctx context.Context) *Client {
	t.Helper()

	dbClient, err := NewClient(ctx, &csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: ":memory:",
	}, nil)
	require.NoError(t, err)

	return dbClient
}

func TestCheckAllowlist(t *testing.T) {
	ctx := t.Context()
	dbClient := getDBClient(t, ctx)

	allowlist, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)

	require.NoError(t, err)

	added, err := dbClient.AddToAllowlist(ctx, allowlist, []*models.AllowlistItem{
		{
			CreatedAt: strfmt.DateTime(time.Now()),
			Value:     "1.2.3.4",
		},
		{
			CreatedAt:   strfmt.DateTime(time.Now()),
			Value:       "8.0.0.0/8",
			Description: "range allowlist",
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
	assert.Equal(t, 5, added)

	// Exatch match
	allowlisted, reason, err := dbClient.IsAllowlisted(ctx, "1.2.3.4")
	require.NoError(t, err)
	require.True(t, allowlisted)
	require.Equal(t, "1.2.3.4 from test", reason)

	// CIDR match
	allowlisted, reason, err = dbClient.IsAllowlisted(ctx, "8.8.8.8")
	require.NoError(t, err)
	require.True(t, allowlisted)
	require.Equal(t, "8.0.0.0/8 from test (range allowlist)", reason)

	// IPv6 match
	allowlisted, reason, err = dbClient.IsAllowlisted(ctx, "2001:db8::1")
	require.NoError(t, err)
	require.True(t, allowlisted)
	require.Equal(t, "2001:db8::/32 from test", reason)

	// Expired item
	allowlisted, reason, err = dbClient.IsAllowlisted(ctx, "2.3.4.5")
	require.NoError(t, err)
	require.False(t, allowlisted)
	require.Empty(t, reason)

	// Decision on a range that contains an allowlisted value
	allowlisted, reason, err = dbClient.IsAllowlisted(ctx, "1.2.3.0/24")
	require.NoError(t, err)
	require.True(t, allowlisted)
	require.Equal(t, "1.2.3.4 from test", reason)

	// No match
	allowlisted, reason, err = dbClient.IsAllowlisted(ctx, "42.42.42.42")
	require.NoError(t, err)
	require.False(t, allowlisted)
	require.Empty(t, reason)

	// IPv6 range that contains an allowlisted value
	allowlisted, reason, err = dbClient.IsAllowlisted(ctx, "8a95:c186:9f96:4c75::/64")
	require.NoError(t, err)
	require.True(t, allowlisted)
	require.Equal(t, "8a95:c186:9f96:4c75:0dad:49c6:ff62:94b8 from test", reason)
}

func TestIsAllowListedBy_SingleAndMultiple(t *testing.T) {
	ctx := t.Context()
	dbClient := getDBClient(t, ctx)

	list1, err := dbClient.CreateAllowList(ctx, "list1", "first list", "", false)
	require.NoError(t, err)
	list2, err := dbClient.CreateAllowList(ctx, "list2", "second list", "", false)
	require.NoError(t, err)

	// Add overlapping and distinct entries
	_, err = dbClient.AddToAllowlist(ctx, list1, []*models.AllowlistItem{
		{Value: "1.1.1.1"},
		{Value: "10.0.0.0/8"},
	})
	require.NoError(t, err)
	_, err = dbClient.AddToAllowlist(ctx, list2, []*models.AllowlistItem{
		{Value: "1.1.1.1"},                   // overlaps with list1
		{Value: "192.168.0.0/16"},            // only in list2
		{Value: "2.2.2.2", Expiration: strfmt.DateTime(time.Now().Add(-time.Hour))}, // expired
	})
	require.NoError(t, err)

	// Exact IP that lives in both
	names, err := dbClient.IsAllowlistedBy(ctx, "1.1.1.1")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"1.1.1.1 from list1", "1.1.1.1 from list2"}, names)

	// IP matching only list1's CIDR
	names, err = dbClient.IsAllowlistedBy(ctx, "10.5.6.7")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8 from list1"}, names)

	// IP matching only list2's CIDR
	names, err = dbClient.IsAllowlistedBy(ctx, "192.168.1.42")
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.0.0/16 from list2"}, names)

	// Expired entry in list2 should not appear
	names, err = dbClient.IsAllowlistedBy(ctx, "2.2.2.2")
	require.NoError(t, err)
	assert.Empty(t, names)
}

func TestIsAllowListedBy_NoMatch(t *testing.T) {
	ctx := t.Context()
	dbClient := getDBClient(t, ctx)

	list, err := dbClient.CreateAllowList(ctx, "solo", "single", "", false)
	require.NoError(t, err)
	_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
		{Value: "5.5.5.5"},
	})
	require.NoError(t, err)

	// completely unrelated IP
	names, err := dbClient.IsAllowlistedBy(ctx, "8.8.4.4")
	require.NoError(t, err)
	assert.Empty(t, names)
}
