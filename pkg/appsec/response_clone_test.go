package appsec

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
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
	orig.UserHeaders["X-New"] = []string{"z"}      // new key
	orig.UserHeaders["X-Test"][0] = "MUT"          // in-place inner-slice write
	orig.UserHTTPCookies = append(orig.UserHTTPCookies, cookie.AppsecCookie{Name: "c2"})

	assert.NotContains(t, clone.UserHeaders, "X-New", "new keys must not leak into the clone")
	assert.Equal(t, "a", clone.UserHeaders["X-Test"][0], "inner slices must be copied, not aliased")
	require.Len(t, clone.UserHTTPCookies, 1, "cookie slice must be copied")
	assert.Equal(t, "c1", clone.UserHTTPCookies[0].Name)
	assert.Equal(t, ChallengeRemediation, clone.Action)
}

// TestAppsecTempResponse_CloneNoRaceWithGenerateResponse reproduces the
// runner→handler pattern: the handler runs GenerateResponse (which writes a
// default CSP header into the map) and json-marshals it, while the runner's
// out-of-band phase keeps writing to the live state.Response via
// SetChallengeHeader. Run under -race, this catches a regression if the Clone()
// at the in-band send is removed.
func TestAppsecTempResponse_CloneNoRaceWithGenerateResponse(t *testing.T) {
	rt := &AppsecRuntimeConfig{
		Logger: log.NewEntry(log.StandardLogger()),
		Config: &AppsecConfig{
			UserBlockedHTTPCode:    http.StatusForbidden,
			BouncerBlockedHTTPCode: http.StatusForbidden,
		},
	}

	state := &AppsecRequestState{
		Response: AppsecTempResponse{
			Action:      ChallengeRemediation,
			UserHeaders: map[string][]string{"Content-Type": {"text/html"}},
		},
	}

	// What the runner hands to the HTTP handler.
	sent := state.Response.Clone()

	var wg sync.WaitGroup
	wg.Add(2)

	// Handler goroutine: GenerateResponse adds the CSP header and we marshal it.
	go func() {
		defer wg.Done()
		for range 1000 {
			_, body := rt.GenerateResponse(sent, rt.Logger)
			_, _ = json.Marshal(body)
		}
	}()

	// Out-of-band goroutine: keep mutating the live state.Response map.
	go func() {
		defer wg.Done()
		for i := range 1000 {
			_ = rt.SetChallengeHeader(state, "X-Oob", string(rune('a'+i%26)))
		}
	}()

	wg.Wait()
}
