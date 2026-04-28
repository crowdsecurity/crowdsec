package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Set CROWDSEC_PG_RACE_TEST=1 to run this test. It expects a Postgres
// instance reachable on 127.0.0.1:5432 with user postgres / password secret.
const pgRaceTestEnv = "CROWDSEC_PG_RACE_TEST"

const (
	pgRaceHost     = "127.0.0.1"
	pgRacePort     = 5432
	pgRaceUser     = "postgres"
	pgRacePassword = "secret"
)

// TestAlertCreateVsFlushOrphansRace reproduces the race between alert ingestion
// and the orphan-events cleanup that runs every minute in production.
//
// On the unfixed code path, Event.CreateBulk and the alert insert that links
// those events run in two separate transactions, exposing a window where
// FlushOrphans can either (a) take row locks that deadlock with the alert's
// AddEvents UPDATE, or (b) delete the events outright, causing ent's O2M edge
// check to fail with "is already connected to a different alert_events".
//
// With CreateAlert wrapped in a single transaction, the in-flight events are
// invisible to FlushOrphans under READ COMMITTED, and neither failure mode
// can occur.
func TestAlertCreateVsFlushOrphansRace(t *testing.T) {
	if os.Getenv(pgRaceTestEnv) == "" {
		t.Skipf("set %s=1 to run (requires postgres on %s:%d, user=%s)",
			pgRaceTestEnv, pgRaceHost, pgRacePort, pgRaceUser)
	}

	ctx := t.Context()
	dbName := fmt.Sprintf("crowdsec_race_test_%d", time.Now().UnixNano())

	createPGDatabase(t, ctx, dbName)
	t.Cleanup(func() { dropPGDatabase(t, dbName) })

	bulkSize := 1000
	dbClient, err := NewClient(ctx, &csconfig.DatabaseCfg{
		Type:             "pgx",
		Host:             pgRaceHost,
		Port:             pgRacePort,
		User:             pgRaceUser,
		Password:         pgRacePassword,
		DbName:           dbName,
		SSLMode:          "disable",
		DecisionBulkSize: bulkSize,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbClient.Close() })

	machineID := "race-test-machine"
	password := strfmt.Password("password")
	_, err = dbClient.CreateMachine(ctx, &machineID, &password, "127.0.0.1", true, true, types.PasswordAuthType)
	require.NoError(t, err)

	const (
		writers         = 8
		alertsPerWriter = 100
		hardTimeout     = 60 * time.Second
	)

	runCtx, cancel := context.WithTimeout(ctx, hardTimeout)
	defer cancel()

	var (
		writersWg     sync.WaitGroup
		deadlockCount atomic.Int64
		edgeErrCount  atomic.Int64
		otherErrCount atomic.Int64
		successCount  atomic.Int64
	)

	// Hot-loop the orphan flush so we don't have to wait for the 1-minute scheduler.
	// Use a dedicated stop channel so the in-flight FlushOrphans call after writers
	// finish completes cleanly instead of being aborted by ctx cancellation.
	stopFlusher := make(chan struct{})
	flusherDone := make(chan struct{})
	go func() {
		defer close(flusherDone)
		for {
			select {
			case <-stopFlusher:
				return
			default:
			}
			dbClient.FlushOrphans(runCtx)
		}
	}()

	for i := range writers {
		writersWg.Add(1)
		go func(workerID int) {
			defer writersWg.Done()
			for j := range alertsPerWriter {
				if runCtx.Err() != nil {
					return
				}

				_, err := dbClient.CreateAlert(runCtx, machineID, makeRaceAlerts(workerID, j, 5))
				switch {
				case err == nil:
					successCount.Add(1)
				case strings.Contains(err.Error(), "deadlock detected"):
					deadlockCount.Add(1)
					t.Logf("worker %d/%d: deadlock: %s", workerID, j, err)
				case strings.Contains(err.Error(), "is already connected to a different alert_events"):
					edgeErrCount.Add(1)
					t.Logf("worker %d/%d: edge constraint: %s", workerID, j, err)
				default:
					otherErrCount.Add(1)
					t.Logf("worker %d/%d: other error: %s", workerID, j, err)
				}
			}
		}(i)
	}

	writersWg.Wait()
	close(stopFlusher)
	<-flusherDone

	t.Logf("alerts succeeded=%d deadlock=%d edge=%d other=%d",
		successCount.Load(), deadlockCount.Load(), edgeErrCount.Load(), otherErrCount.Load())

	require.Zero(t, deadlockCount.Load(), "got %d deadlocks between CreateAlert and FlushOrphans", deadlockCount.Load())
	require.Zero(t, edgeErrCount.Load(), "got %d edge-constraint errors (events deleted out from under alert insert)", edgeErrCount.Load())
	require.Zero(t, otherErrCount.Load(), "got %d unexpected errors", otherErrCount.Load())
	require.Positive(t, successCount.Load(), "no alerts were inserted at all — test setup is wrong")
}

// makeRaceAlerts builds a batch of distinct alerts with several events and a
// decision each, so the create path actually exercises Event.CreateBulk plus
// the alert↔events O2M edge update plus decision attachment.
func makeRaceAlerts(workerID, batchID, eventsPerAlert int) []*models.Alert {
	now := time.Now().UTC().Format(time.RFC3339)

	scenario := "test/race"
	scenarioVersion := "0.1"
	scenarioHash := "deadbeef"
	message := fmt.Sprintf("worker %d batch %d", workerID, batchID)
	leakSpeed := "10s"
	scope := "Ip"
	value := fmt.Sprintf("10.%d.%d.%d", workerID%256, (batchID/256)%256, batchID%256)
	capacity := int32(5)
	eventsCount := int32(eventsPerAlert)
	simulated := false
	duration := "1h"
	decisionType := "ban"
	origin := "test"
	uuid := fmt.Sprintf("uuid-%d-%d-%d", workerID, batchID, time.Now().UnixNano())

	events := make([]*models.Event, eventsPerAlert)
	ts := now
	for i := range events {
		events[i] = &models.Event{
			Timestamp: &ts,
			Meta: models.Meta{
				{Key: "source_ip", Value: value},
				{Key: "iter", Value: fmt.Sprintf("%d", i)},
			},
		}
	}

	return []*models.Alert{
		{
			Capacity:        &capacity,
			Scenario:        &scenario,
			ScenarioVersion: &scenarioVersion,
			ScenarioHash:    &scenarioHash,
			Message:         &message,
			Leakspeed:       &leakSpeed,
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
			Events: events,
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
		},
	}
}

func createPGDatabase(t *testing.T, ctx context.Context, dbName string) {
	t.Helper()

	adminDSN := fmt.Sprintf("host=%s port=%d user=%s dbname=postgres password=%s sslmode=disable",
		pgRaceHost, pgRacePort, pgRaceUser, pgRacePassword)

	adminDB, err := sql.Open("pgx", adminDSN)
	require.NoError(t, err, "connecting to admin postgres database")
	defer adminDB.Close()

	_, err = adminDB.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName))
	require.NoError(t, err)
	_, err = adminDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s", dbName))
	require.NoError(t, err)
}

func dropPGDatabase(t *testing.T, dbName string) {
	t.Helper()

	adminDSN := fmt.Sprintf("host=%s port=%d user=%s dbname=postgres password=%s sslmode=disable",
		pgRaceHost, pgRacePort, pgRaceUser, pgRacePassword)

	adminDB, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Logf("cleanup: open admin db: %s", err)
		return
	}
	defer adminDB.Close()

	// t.Context() is already canceled by the time Cleanup runs, so use a fresh one.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second) //nolint:usetesting
	defer cancel()

	// terminate any leftover connections so DROP doesn't get rejected
	_, _ = adminDB.ExecContext(cleanupCtx, fmt.Sprintf(
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s' AND pid <> pg_backend_pid()",
		dbName))
	if _, err := adminDB.ExecContext(cleanupCtx, fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName)); err != nil {
		t.Logf("cleanup: drop db %s: %s", dbName, err)
	}
}
