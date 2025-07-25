package setup

import (
	"testing"

	"github.com/stretchr/testify/require"
)


func TestUnitEnabled(t *testing.T) {
	ctx := t.Context()

	env := NewExprSystemd(UnitMap{"crowdsec-setup-installed.service": struct{}{}}, []string{})

	installed, err := env.UnitEnabled(ctx, "crowdsec-setup-installed.service")
	require.NoError(t, err)
	require.True(t, installed)

	installed, err = env.UnitEnabled(ctx, "crowdsec-setup-missing.service")
	require.NoError(t, err)
	require.False(t, installed)
}
