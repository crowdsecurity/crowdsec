package cookie

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppsecCookieString(t *testing.T) {
	tests := []struct {
		name   string
		cookie *AppsecCookie
		want   string
	}{
		{
			name:   "default is lax",
			cookie: NewAppsecCookie("c").Value("v"),
			want:   "c=v; Path=/; SameSite=Lax",
		},
		{
			name:   "none implies secure",
			cookie: NewAppsecCookie("c").Value("v").SameSite(SameSiteNone),
			want:   "c=v; Path=/; Secure; SameSite=None",
		},
		{
			name:   "partitioned implies secure",
			cookie: NewAppsecCookie("c").Value("v").Partitioned(),
			want:   "c=v; Path=/; Secure; SameSite=Lax; Partitioned",
		},
		{
			name:   "none partitioned",
			cookie: NewAppsecCookie("c").Value("v").HttpOnly().SameSite(SameSiteNone).Partitioned(),
			want:   "c=v; Path=/; HttpOnly; Secure; SameSite=None; Partitioned",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.cookie.String())
		})
	}
}
