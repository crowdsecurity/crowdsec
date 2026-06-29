package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func registerFlushTestMachine(t *testing.T, ctx context.Context, c *Client, machineID string) {
	t.Helper()

	password := strfmt.Password("password")
	_, err := c.CreateMachine(ctx, &machineID, &password, "127.0.0.1", true, true, types.PasswordAuthType)
	require.NoError(t, err)
}

// makeFlushAlert builds a single alert for the flush tests. When withActiveDecision
// is true the alert carries a decision that stays active for a year, otherwise it
// has no decision at all.
func makeFlushAlert(value string, withActiveDecision bool) *models.Alert {
	now := time.Now().UTC().Format(time.RFC3339)

	scenario := "test/flush"
	scenarioVersion := "0.1"
	scenarioHash := "deadbeef"
	leakSpeed := "10s"
	scope := "Ip"
	simulated := false
	message := "flush test"
	capacity := int32(1)
	eventsCount := int32(1)
	uuid := fmt.Sprintf("uuid-%s-%d", value, time.Now().UnixNano())

	alert := &models.Alert{
		Capacity:        &capacity,
		Scenario:        &scenario,
		ScenarioVersion: &scenarioVersion,
		ScenarioHash:    &scenarioHash,
		Leakspeed:       &leakSpeed,
		Message:         &message,
		EventsCount:     &eventsCount,
		Simulated:       &simulated,
		StartAt:         &now,
		StopAt:          &now,
		UUID:            uuid,
		Source: &models.Source{
			Scope: &scope,
			Value: &value,
			IP:    value,
		},
	}

	if withActiveDecision {
		duration := "8760h"
		decisionType := "ban"
		origin := "test"

		alert.Decisions = []*models.Decision{
			{
				Duration:  &duration,
				Type:      &decisionType,
				Scope:     &scope,
				Value:     &value,
				Origin:    &origin,
				Scenario:  &scenario,
				Simulated: &simulated,
			},
		}
	}

	return alert
}

func remainingAlertValues(t *testing.T, ctx context.Context, c *Client) map[string]bool {
	t.Helper()

	alerts, err := c.Ent.Alert.Query().All(ctx)
	require.NoError(t, err)

	out := make(map[string]bool, len(alerts))
	for _, a := range alerts {
		out[a.SourceValue] = true
	}

	return out
}

// TestFlushAlerts_MaxAgeKeepsActiveDecisions ensures the max_age flush path does
// not delete an alert that still carries an active decision (which would
// cascade-delete the live decision).
func TestFlushAlerts_MaxAgeKeepsActiveDecisions(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	machineID := "flush-test-machine"
	registerFlushTestMachine(t, ctx, c, machineID)

	_, err := c.CreateAlert(ctx, machineID, []*models.Alert{
		makeFlushAlert("1.2.3.4", true),  // active decision -> must survive
		makeFlushAlert("5.6.7.8", false), // no decision -> deletable
	})
	require.NoError(t, err)

	// All alerts are now older than this tiny maxAge, so only the active-decision
	// guard decides what survives.
	time.Sleep(20 * time.Millisecond)

	require.NoError(t, c.FlushAlerts(ctx, 5*time.Millisecond, 0))

	remaining := remainingAlertValues(t, ctx, c)
	require.True(t, remaining["1.2.3.4"], "alert with an active decision must not be flushed by max_age")
	require.False(t, remaining["5.6.7.8"], "alert without a decision should be flushed by max_age")

	// The live decision must still be present.
	decCount, err := c.Ent.Decision.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, decCount, "active decision must not be cascade-deleted")
}

// TestFlushAlerts_MaxItemsKeepsActiveDecisions ensures the max_items flush path
// keeps alerts with active decisions even when they are among the oldest by id.
func TestFlushAlerts_MaxItemsKeepsActiveDecisions(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	machineID := "flush-test-machine"
	registerFlushTestMachine(t, ctx, c, machineID)

	// Created oldest-first. The first alert carries an active decision and is the
	// oldest by id, so a naive max_items prune would delete it (and its decision).
	for i, a := range []*models.Alert{
		makeFlushAlert("10.0.0.1", true),  // oldest, active decision -> must survive
		makeFlushAlert("10.0.0.2", false), // oldest range, deletable
		makeFlushAlert("10.0.0.3", false),
		makeFlushAlert("10.0.0.4", false),
		makeFlushAlert("10.0.0.5", false), // newest
	} {
		_, err := c.CreateAlert(ctx, machineID, []*models.Alert{a})
		require.NoError(t, err, "alert %d", i)
	}

	require.NoError(t, c.FlushAlerts(ctx, 0, 2))

	remaining := remainingAlertValues(t, ctx, c)
	require.True(t, remaining["10.0.0.1"], "alert with an active decision must survive max_items pruning")
	require.False(t, remaining["10.0.0.2"], "oldest alert without a decision should be pruned")

	decCount, err := c.Ent.Decision.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, decCount, "active decision must not be cascade-deleted")
}
