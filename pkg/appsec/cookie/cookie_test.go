package cookie

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPartitionedCookie(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cookie *AppsecCookie
	}{
		{name: "builder", cookie: NewAppsecCookie("clearance").SameSite(SameSiteNone).Partitioned()},
		{name: "struct", cookie: &AppsecCookie{Name: "clearance", PartitionedFlag: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := http.ParseSetCookie(tc.cookie.String())
			require.NoError(t, err)
			require.NoError(t, parsed.Valid())
			require.True(t, parsed.Partitioned)
			require.True(t, parsed.Secure)
		})
	}
}
