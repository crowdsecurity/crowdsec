package appsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
)

// TestAppsecTempResponse_Clone asserts the clone's reference-typed fields have
// independent backing: mutating the original (as the out-of-band phase does)
// must not be visible through the clone the HTTP handler holds.
func TestAppsecTempResponse_Clone(t *testing.T) {
	orig := AppsecTempResponse{
		Action:          ChallengeRemediation,
		UserHeaders:     map[string][]string{"X-Test": {"a"}},
		UserHTTPCookies: []cookie.AppsecCookie{{Name: "c1"}},
	}

	clone := orig.Clone()

	// Out-of-band-style mutations on the original.
	orig.UserHeaders["X-New"] = []string{"z"} // new key
	orig.UserHeaders["X-Test"][0] = "MUT"     // in-place inner-slice write
	orig.UserHTTPCookies = append(orig.UserHTTPCookies, cookie.AppsecCookie{Name: "c2"})

	assert.NotContains(t, clone.UserHeaders, "X-New", "new keys must not leak into the clone")
	assert.Equal(t, "a", clone.UserHeaders["X-Test"][0], "inner slices must be copied, not aliased")
	require.Len(t, clone.UserHTTPCookies, 1, "cookie slice must be copied")
	assert.Equal(t, "c1", clone.UserHTTPCookies[0].Name)
	assert.Equal(t, ChallengeRemediation, clone.Action)
}
