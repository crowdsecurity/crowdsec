package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
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

// createDecision is a test helper that creates a decision directly via ent,
// bypassing the full alert pipeline.
func createDecision(t *testing.T, ctx context.Context, client *ent.Client, value string, until time.Time) {
	t.Helper()

	rng, err := csnet.NewRange(value)
	require.NoError(t, err)

	_, err = client.Decision.Create().
		SetUntil(until).
		SetScenario("test").
		SetType("ban").
		SetScope("Ip").
		SetValue(value).
		SetOrigin("test").
		SetIPSize(int64(rng.Size())).
		SetStartIP(rng.Start.Addr).
		SetStartSuffix(rng.Start.Sfx).
		SetEndIP(rng.End.Addr).
		SetEndSuffix(rng.End.Sfx).
		Save(ctx)
	require.NoError(t, err)
}

func TestApplyAllowlistsToExistingDecisions(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)

	t.Run("no allowlist items", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "1.2.3.4", future)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("ipv4 exact match", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "1.2.3.4", future)
		createDecision(t, ctx, dbClient.Ent, "5.6.7.8", future) // should not be affected

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "1.2.3.4"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Verify the right decision was expired
		remaining, err := dbClient.Ent.Decision.Query().All(ctx)
		require.NoError(t, err)
		require.Len(t, remaining, 2)

		for _, d := range remaining {
			if d.Value == "1.2.3.4" {
				assert.True(t, d.Until.Before(future), "decision should have been expired")
			} else {
				assert.True(t, d.Until.Equal(future), "unrelated decision should not be affected")
			}
		}
	})

	t.Run("ipv4 decision inside allowlist range", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "10.0.1.5", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "10.0.0.0/16"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("ipv4 decision contains allowlist IP", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "10.0.0.0/8", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "10.5.6.7"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("ipv4 no overlap", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "1.2.3.4", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "9.9.9.9"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("ipv6 exact match", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "2001:db8::1", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "2001:db8::1"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("ipv6 decision inside allowlist range", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "2001:db8::1", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "2001:db8::/32"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("ipv6 decision contains allowlist IP", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "2001:db8::/32", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "2001:db8::1"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("ipv6 no overlap", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "2001:db8::1", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "fe80::1"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("mixed ipv4 and ipv6", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "1.2.3.4", future)
		createDecision(t, ctx, dbClient.Ent, "2001:db8::1", future)
		createDecision(t, ctx, dbClient.Ent, "9.9.9.9", future) // no match

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "1.2.3.4"},
			{Value: "2001:db8::/32"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, count)
	})

	t.Run("expired allowlist items are ignored", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "1.2.3.4", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "1.2.3.4", Expiration: strfmt.DateTime(time.Now().Add(-time.Hour))},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("already expired decisions are not affected", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		past := time.Now().UTC().Add(-time.Hour)
		createDecision(t, ctx, dbClient.Ent, "1.2.3.4", past)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "1.2.3.4"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("multiple allowlist items matching same decision", func(t *testing.T) {
		ctx := t.Context()
		dbClient := getDBClient(t, ctx)

		createDecision(t, ctx, dbClient.Ent, "10.0.1.5", future)

		list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
		require.NoError(t, err)
		_, err = dbClient.AddToAllowlist(ctx, list, []*models.AllowlistItem{
			{Value: "10.0.0.0/16"},
			{Value: "10.0.0.0/8"},
		})
		require.NoError(t, err)

		count, err := dbClient.ApplyAllowlistsToExistingDecisions(ctx)
		require.NoError(t, err)
		// Decision is only expired once even though two allowlist items match
		assert.Equal(t, 1, count)
	})
}

func TestApplyAllowlistBatch_BatchBoundary(t *testing.T) {
	ctx := t.Context()
	dbClient := getDBClient(t, ctx)
	future := time.Now().UTC().Add(24 * time.Hour)

	// Create decisions that will match allowlist items across batch boundaries
	for i := 1; i <= 5; i++ {
		createDecision(t, ctx, dbClient.Ent, fmt.Sprintf("10.0.0.%d", i), future)
	}

	list, err := dbClient.CreateAllowList(ctx, "test", "test", "", false)
	require.NoError(t, err)

	items := make([]*models.AllowlistItem, 5)
	for i := 1; i <= 5; i++ {
		items[i-1] = &models.AllowlistItem{Value: fmt.Sprintf("10.0.0.%d", i)}
	}

	_, err = dbClient.AddToAllowlist(ctx, list, items)
	require.NoError(t, err)

	// Use a small batch size to force multiple batches
	count, err := dbClient.applyAllowlistBatch(ctx, func() []*ent.AllowListItem {
		items, err := dbClient.Ent.AllowListItem.Query().All(ctx)
		require.NoError(t, err)
		return items
	}(), 4, time.Now().UTC(), 2)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}
