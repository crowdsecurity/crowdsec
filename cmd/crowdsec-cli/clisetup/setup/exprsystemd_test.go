package setup

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnitInstalled(t *testing.T) {
	ctx := t.Context()

	env := NewExprSystemd(UnitMap{"crowdsec-setup-installed.service": UnitInfo{}}, nullLogger())

	installed, err := env.UnitInstalled(ctx, "crowdsec-setup-installed.service")
	require.NoError(t, err)
	require.True(t, installed)

	installed, err = env.UnitInstalled(ctx, "crowdsec-setup-missing.service")
	require.NoError(t, err)
	require.False(t, installed)
}
