package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// makeDecisionsScenarioAlert builds a single alert carrying one active decision, for
// the QueryDecisionCountByScenario tests. Reuses the "8760h" duration convention from
// flush_test.go's makeFlushAlert so the decision stays active for the test's lifetime.
func makeDecisionsScenarioAlert(value string) *models.Alert {
	now := time.Now().UTC().Format(time.RFC3339)

	scenario := "test/decisions-by-scenario"
	scenarioVersion := "0.1"
	scenarioHash := "deadbeef"
	leakSpeed := "10s"
	scope := "Ip"
	simulated := false
	message := "decisions by scenario test"
	capacity := int32(1)
	eventsCount := int32(1)
	uuid := fmt.Sprintf("uuid-%s-%d", value, time.Now().UnixNano())
	duration := "8760h"
	decisionType := "ban"
	origin := "test"

	return &models.Alert{
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
		Decisions: []*models.Decision{
			{
				Duration:  &duration,
				Type:      &decisionType,
				Scope:     &scope,
				Value:     &value,
				Origin:    &origin,
				Scenario:  &scenario,
				Simulated: &simulated,
			},
		},
	}
}

// TestQueryDecisionCountByScenario_MachineOwnedAlert ensures a decision belonging to
// an alert owned by a machine resolves to that machine's ID in the Machine field.
func TestQueryDecisionCountByScenario_MachineOwnedAlert(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	machineID := "decisions-test-machine"
	registerFlushTestMachine(t, ctx, c, machineID)

	_, err := c.CreateAlert(ctx, machineID, []*models.Alert{
		makeDecisionsScenarioAlert("1.2.3.4"),
	})
	require.NoError(t, err)

	rows, err := c.QueryDecisionCountByScenario(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, machineID, rows[0].Machine)
	require.Equal(t, 1, rows[0].Count)
}

// TestQueryDecisionCountByScenario_NoOwningMachine ensures a decision belonging to an
// alert with no owning machine falls back to "N/A" in the Machine field.
func TestQueryDecisionCountByScenario_NoOwningMachine(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	_, err := c.CreateAlert(ctx, "", []*models.Alert{
		makeDecisionsScenarioAlert("1.2.3.4"),
	})
	require.NoError(t, err)

	rows, err := c.QueryDecisionCountByScenario(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "N/A", rows[0].Machine)
}

// TestQueryDecisionCountByScenario_FoldsSameMachineAcrossAlerts ensures two separate
// alerts owned by the same machine, sharing scenario/origin/type on their decisions,
// fold into a single row with the summed count rather than staying split per alert.
func TestQueryDecisionCountByScenario_FoldsSameMachineAcrossAlerts(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	machineID := "decisions-test-machine"
	registerFlushTestMachine(t, ctx, c, machineID)

	_, err := c.CreateAlert(ctx, machineID, []*models.Alert{makeDecisionsScenarioAlert("1.2.3.4")})
	require.NoError(t, err)
	_, err = c.CreateAlert(ctx, machineID, []*models.Alert{makeDecisionsScenarioAlert("5.6.7.8")})
	require.NoError(t, err)

	rows, err := c.QueryDecisionCountByScenario(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, machineID, rows[0].Machine)
	require.Equal(t, 2, rows[0].Count)
}

// TestQueryDecisionCountByScenario_SplitsAcrossDifferentMachines ensures alerts owned
// by distinct machines, sharing scenario/origin/type on their decisions, are reported
// as separate rows rather than merged - while the sum of their counts still matches
// what a pre-change single (scenario, origin, type) row would have reported.
func TestQueryDecisionCountByScenario_SplitsAcrossDifferentMachines(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	machine1 := "decisions-test-machine-1"
	machine2 := "decisions-test-machine-2"
	registerFlushTestMachine(t, ctx, c, machine1)
	registerFlushTestMachine(t, ctx, c, machine2)

	_, err := c.CreateAlert(ctx, machine1, []*models.Alert{makeDecisionsScenarioAlert("1.2.3.4")})
	require.NoError(t, err)
	_, err = c.CreateAlert(ctx, machine2, []*models.Alert{makeDecisionsScenarioAlert("5.6.7.8")})
	require.NoError(t, err)

	rows, err := c.QueryDecisionCountByScenario(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	countByMachine := make(map[string]int, len(rows))
	total := 0

	for _, row := range rows {
		countByMachine[row.Machine] = row.Count
		total += row.Count
	}

	require.Equal(t, 1, countByMachine[machine1])
	require.Equal(t, 1, countByMachine[machine2])
	require.Equal(t, 2, total)
}
