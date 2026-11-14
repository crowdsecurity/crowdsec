package database

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func TestDecisionIndexMigration(t *testing.T) {
	tests := []struct {
		name    string
		columns string
	}{
		{"decision_value", "value"},
		{"decision_value_type_scope_until", "value, type, scope, until"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			config := &csconfig.DatabaseCfg{Type: "sqlite", DbPath: filepath.Join(t.TempDir(), "test.db")}
			c, err := NewClient(ctx, config, nil)
			require.NoError(t, err)
			d, err := c.Ent.Decision.Create().
				SetUntil(time.Now().UTC().Truncate(time.Second)).
				SetScenario("test/index-migration").
				SetType("ban").
				SetScope("Ip").
				SetValue("192.0.2.1").
				SetOrigin("crowdsec").
				SetSimulated(true).
				Save(ctx)
			require.NoError(t, err)
			require.NoError(t, c.Close())

			typ, _, err := config.ConnectionDialect()
			require.NoError(t, err)
			dsn, err := config.ConnectionString()
			require.NoError(t, err)
			db, err := sql.Open(typ, dsn)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })

			for _, query := range []string{
				"DROP INDEX decision_value_type_scope_until_simulated",
				"CREATE INDEX " + tc.name + " ON decisions (" + tc.columns + ")",
				"CREATE INDEX operator_decision_scenario ON decisions (scenario)",
			} {
				_, err := db.ExecContext(ctx, query)
				require.NoError(t, err)
			}

			for range 2 {
				c, err := NewClient(ctx, config, nil)
				require.NoError(t, err)
				got, err := c.Ent.Decision.Get(ctx, d.ID)
				require.NoError(t, err)
				require.Equal(t, d.Value, got.Value)
				require.Equal(t, d.Until, got.Until)
				require.True(t, got.Simulated)
				require.NoError(t, c.Close())

				var count int
				err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('decision_value', 'decision_value_type_scope_until')").Scan(&count)
				require.NoError(t, err)
				require.Zero(t, count)
				err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('decision_value_type_scope_until_simulated', 'operator_decision_scenario')").Scan(&count)
				require.NoError(t, err)
				require.Equal(t, 2, count)
				var columns string
				err = db.QueryRowContext(ctx, "SELECT group_concat(name, ',') FROM (SELECT name FROM pragma_index_info('decision_value_type_scope_until_simulated') ORDER BY seqno)").Scan(&columns)
				require.NoError(t, err)
				require.Equal(t, "value,type,scope,until,simulated", columns)
			}
		})
	}
}
