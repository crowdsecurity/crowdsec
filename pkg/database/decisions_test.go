package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLatestDecisionID(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	latest, err := c.LatestDecisionID(ctx)
	require.NoError(t, err)
	require.Zero(t, latest, "empty table has no cursor")

	var lastID int

	for range 3 {
		d, err := c.Ent.Decision.Create().
			SetUntil(time.Now().UTC().Add(time.Hour)).
			SetScenario("test").
			SetType("ban").
			SetScope("Ip").
			SetValue("1.2.3.4").
			SetOrigin("test").
			Save(ctx)
		require.NoError(t, err)

		lastID = d.ID
	}

	latest, err = c.LatestDecisionID(ctx)
	require.NoError(t, err)
	require.Equal(t, lastID, latest)

	// deleting the newest rows rewinds the cursor, but ids are never reused
	_, err = c.Ent.Decision.Delete().Exec(ctx)
	require.NoError(t, err)

	latest, err = c.LatestDecisionID(ctx)
	require.NoError(t, err)
	require.Zero(t, latest)

	d, err := c.Ent.Decision.Create().
		SetUntil(time.Now().UTC().Add(time.Hour)).
		SetScenario("test").
		SetType("ban").
		SetScope("Ip").
		SetValue("1.2.3.5").
		SetOrigin("test").
		Save(ctx)
	require.NoError(t, err)
	require.Greater(t, d.ID, lastID, "decision ids must keep climbing across deletes")
}
