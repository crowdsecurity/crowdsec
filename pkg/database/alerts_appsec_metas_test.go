package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Set CROWDSEC_MYSQL_APPSEC_ALERT_TEST=1 to run against MySQL on 127.0.0.1:3306.
// Exercises the AppSec alert insert path: multiple events + alert-level metas, kind=waf.
const mysqlAppsecAlertTestEnv = "CROWDSEC_MYSQL_APPSEC_ALERT_TEST"

const (
	mysqlMetasHost     = "127.0.0.1"
	mysqlMetasPort     = 3306
	mysqlMetasUser     = "crowdsec"
	mysqlMetasPassword = "crowdsec"
)

func TestCreateAppsecLikeAlert_SQLite(t *testing.T) {
	ctx := t.Context()

	dbClient, err := NewClient(ctx, &csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: ":memory:",
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbClient.Close() })

	runAppsecAlertInsertTest(t, ctx, dbClient)
}

func TestCreateAppsecLikeAlert_MySQL(t *testing.T) {
	if os.Getenv(mysqlAppsecAlertTestEnv) == "" {
		t.Skipf("set %s=1 to run (requires mysql on %s:%d)", mysqlAppsecAlertTestEnv, mysqlMetasHost, mysqlMetasPort)
	}

	ctx := t.Context()
	dbName := fmt.Sprintf("crowdsec_metas_test_%d", time.Now().UnixNano())

	user := envOrDefault("CROWDSEC_MYSQL_USER", mysqlMetasUser)
	password := envOrDefault("CROWDSEC_MYSQL_PASSWORD", mysqlMetasPassword)

	createMySQLDatabase(t, ctx, dbName, user, password)
	t.Cleanup(func() { dropMySQLDatabase(t, dbName, user, password) })

	dbClient, err := NewClient(ctx, &csconfig.DatabaseCfg{
		Type:     "mysql",
		Host:     mysqlMetasHost,
		Port:     mysqlMetasPort,
		User:     user,
		Password: password,
		DbName:   dbName,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbClient.Close() })

	runAppsecAlertInsertTest(t, ctx, dbClient)
}

func runAppsecAlertInsertTest(t *testing.T, ctx context.Context, dbClient *Client) {
	t.Helper()

	machineID := "appsec-metas-test"
	pw := strfmt.Password("password")
	_, err := dbClient.CreateMachine(ctx, &machineID, &pw, "127.0.0.1", true, true, types.PasswordAuthType)
	require.NoError(t, err)

	// Single alert (typical AppSec POST)
	ids, err := dbClient.CreateAlert(ctx, machineID, []*models.Alert{makeAppsecLikeAlert(0)})
	require.NoError(t, err, "single appsec-like alert insert failed")
	require.Len(t, ids, 1)

	// Batch of distinct alerts (exercises former CreateBulk path)
	batch := make([]*models.Alert, 5)
	for i := range batch {
		batch[i] = makeAppsecLikeAlert(i)
	}

	ids, err = dbClient.CreateAlert(ctx, machineID, batch)
	require.NoError(t, err, "batched appsec-like alert insert failed")
	require.Len(t, ids, len(batch))
}

// makeAppsecLikeAlert mirrors the AppSec payload shape: multiple events,
// alert-level context metas (~7 keys), kind=waf, no decisions.
func makeAppsecLikeAlert(seed int) *models.Alert {
	now := time.Now().UTC().Format(time.RFC3339)

	scenario := "crowdsecurity/vpatch-env-access"
	scenarioVersion := "0.1"
	scenarioHash := "deadbeef"
	message := "AppSec detected a threat"
	leakSpeed := ""
	scope := "Ip"
	value := fmt.Sprintf("185.157.63.%d", seed+18)
	capacity := int32(1)
	eventsCount := int32(3)
	simulated := false
	kind := types.WAFAlertKind.String()
	remediation := true

	events := make([]*models.Event, 3)
	for i := range events {
		ts := now
		events[i] = &models.Event{
			Timestamp: &ts,
			Meta: models.Meta{
				{Key: "rule_name", Value: scenario},
				{Key: "uri", Value: "/.env"},
				{Key: "message", Value: "Env file access"},
			},
		}
	}

	alertMeta := models.Meta{
		{Key: "method", Value: "GET"},
		{Key: "uri", Value: "/.env"},
		{Key: "rules", Value: "crowdsecurity/vpatch-env-access"},
		{Key: "id", Value: fmt.Sprintf("rule-%d", seed)},
		{Key: "name", Value: scenario},
		{Key: "target_fqdn", Value: "test.example.com"},
		{Key: "matched_zones", Value: "REQUEST_URI"},
	}

	return &models.Alert{
		UUID:            uuid.NewString(),
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
		Kind:            kind,
		Remediation:     remediation,
		Source: &models.Source{
			Scope: &scope,
			Value: &value,
			IP:    value,
		},
		Events: events,
		Meta:   alertMeta,
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}

func createMySQLDatabase(t *testing.T, ctx context.Context, dbName, user, password string) {
	t.Helper()

	adminDSN := fmt.Sprintf("%s:%s@tcp(%s:%d)/", user, password, mysqlMetasHost, mysqlMetasPort)

	adminDB, err := sql.Open("mysql", adminDSN)
	require.NoError(t, err, "connecting to admin mysql")
	defer adminDB.Close()

	_, err = adminDB.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName))
	require.NoError(t, err)
	_, err = adminDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE `%s`", dbName))
	require.NoError(t, err)
}

func dropMySQLDatabase(t *testing.T, dbName, user, password string) {
	t.Helper()

	adminDSN := fmt.Sprintf("%s:%s@tcp(%s:%d)/", user, password, mysqlMetasHost, mysqlMetasPort)

	adminDB, err := sql.Open("mysql", adminDSN)
	if err != nil {
		t.Logf("cleanup: open admin db: %s", err)
		return
	}
	defer adminDB.Close()

	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second) //nolint:usetesting
	defer cancel()

	if _, err := adminDB.ExecContext(cleanupCtx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName)); err != nil {
		t.Logf("cleanup: drop db %s: %s", dbName, err)
	}
}
