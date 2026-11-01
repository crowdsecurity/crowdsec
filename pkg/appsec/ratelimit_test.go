package appsec

import (
	"testing"
	"testing/synctest"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func TestParseRateLimitSpec(t *testing.T) {
	tests := []struct {
		limit      string
		wantCount  int
		wantPeriod time.Duration
		wantErr    string
	}{
		{limit: "1/m", wantCount: 1, wantPeriod: time.Minute},
		{limit: "10/s", wantCount: 10, wantPeriod: time.Second},
		{limit: "100/h", wantCount: 100, wantPeriod: time.Hour},
		{limit: "1/5m", wantErr: "unit must be s, m or h"},
		{limit: "10/d", wantErr: "unit must be s, m or h"},
		{limit: "0/m", wantErr: "count must be a positive integer"},
		{limit: "-1/m", wantErr: "count must be a positive integer"},
		{limit: "x/m", wantErr: "count must be a positive integer"},
		{limit: "10", wantErr: "expected <count>/<s|m|h>"},
		{limit: "", wantErr: "expected <count>/<s|m|h>"},
	}

	for _, tc := range tests {
		t.Run(tc.limit, func(t *testing.T) {
			spec, err := parseRateLimitSpec("login", tc.limit)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantCount, spec.count)
			require.Equal(t, tc.wantPeriod, spec.period)
		})
	}
}

func TestRateLimitIdentity(t *testing.T) {
	tests := []struct {
		name      string
		a, b      [2]string // {clientIP, sourceValue}
		wantEqual bool
	}{
		{"same ipv6 /64", [2]string{"2001:db8::1", ""}, [2]string{"2001:db8::ffff:1", ""}, true},
		{"different ipv6 /64", [2]string{"2001:db8:0:1::1", ""}, [2]string{"2001:db8:0:2::1", ""}, false},
		{"ipv4-mapped is its ipv4", [2]string{"::ffff:5.6.7.8", ""}, [2]string{"5.6.7.8", ""}, true},
		{"different ipv4", [2]string{"5.6.7.8", ""}, [2]string{"5.6.7.9", ""}, false},
		{"source value ignores ip", [2]string{"5.6.7.8", "sess1"}, [2]string{"1.1.1.1", "sess1"}, true},
		{"different source values", [2]string{"5.6.7.8", "sess1"}, [2]string{"5.6.7.8", "sess2"}, false},
		// An attacker sending cookie=5.6.7.8 must not share 5.6.7.8's budget.
		{"source value spelling an ip", [2]string{"1.1.1.1", "5.6.7.8"}, [2]string{"5.6.7.8", ""}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := rateLimitIdentityFor(tc.a[0], tc.a[1])
			b := rateLimitIdentityFor(tc.b[0], tc.b[1])
			require.Equal(t, tc.wantEqual, a == b, "%+v vs %+v", a, b)
		})
	}
}

func newTestLimiter(t *testing.T, limit string) *rateLimiter {
	t.Helper()

	spec, err := parseRateLimitSpec("k", limit)
	require.NoError(t, err)

	return newRateLimits("test", map[string]rateLimitSpec{"k": spec}).get("k")
}

func TestRateLimiterBurstAndRefill(t *testing.T) {
	l := newTestLimiter(t, "3/m")
	id := rateLimitIdentityFor("1.2.3.4", "")
	t0 := time.Now()

	for i := range 3 {
		require.True(t, l.take(id, t0), "request %d is within the burst", i)
	}

	require.False(t, l.take(id, t0))
	require.True(t, l.take(rateLimitIdentityFor("1.2.3.5", ""), t0), "other sources have their own budget")

	// 3/m refills one token every 20s.
	require.False(t, l.take(id, t0.Add(19*time.Second)))
	require.True(t, l.take(id, t0.Add(25*time.Second)))
	require.False(t, l.take(id, t0.Add(25*time.Second)))
}

func TestRateLimiterAlertsOnce(t *testing.T) {
	l := newTestLimiter(t, "1/s")
	id := rateLimitIdentityFor("1.2.3.4", "")
	t0 := time.Now()

	require.True(t, l.take(id, t0))
	require.False(t, l.take(id, t0))
	require.True(t, l.claimAlert(id))

	// Back under the limit, then over again: no second alert.
	require.True(t, l.take(id, t0.Add(time.Second)))
	require.False(t, l.take(id, t0.Add(time.Second)))
	require.False(t, l.claimAlert(id))
}

func TestRateLimiterSweep(t *testing.T) {
	l := newTestLimiter(t, "1/m")
	idle := rateLimitIdentityFor("1.1.1.1", "")
	busy := rateLimitIdentityFor("2.2.2.2", "")
	t0 := time.Now()

	l.take(idle, t0)
	l.take(busy, t0)
	// Denied, but still activity: it must keep the entry, and its alert state.
	require.False(t, l.take(busy, t0.Add(30*time.Second)))
	require.True(t, l.claimAlert(busy))

	l.sweep(t0.Add(time.Minute - time.Nanosecond))
	require.Len(t, l.entries, 2)

	l.sweep(t0.Add(time.Minute))
	require.Len(t, l.entries, 1)
	require.Contains(t, l.entries, busy)
	require.False(t, l.claimAlert(busy))

	l.sweep(t0.Add(90 * time.Second))
	require.Empty(t, l.entries)
}

func TestRateLimitSweeperRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		spec, err := parseRateLimitSpec("k", "1/m")
		require.NoError(t, err)

		limits := newRateLimits("test", map[string]rateLimitSpec{"k": spec})
		l := limits.get("k")
		l.take(rateLimitIdentityFor("1.2.3.4", ""), time.Now())

		done := make(chan struct{})
		stopped := make(chan struct{})

		go func() {
			limits.RunSweepers(done)
			close(stopped)
		}()

		time.Sleep(time.Minute)
		synctest.Wait()
		require.Empty(t, l.entries)

		close(done)
		<-stopped
	})
}

func TestRateLimitLoad(t *testing.T) {
	tests := []struct {
		name     string
		cfg      AppsecConfig
		wantErr  string
		wantKeys []string
	}{
		{
			name:     "two and three argument forms",
			cfg:      AppsecConfig{PreEval: []Hook{{Apply: []string{`RateLimit("a", "1/m")`, `RateLimit("b", "10/s", req.Header.Get("X-Session"))`}}}},
			wantKeys: []string{"a", "b"},
		},
		{
			name:     "phase-scoped pre_eval",
			cfg:      AppsecConfig{InBand: &AppsecPhaseConfig{PreEval: []Hook{{Filter: `RateLimit("a", "1/m")`}}}},
			wantKeys: []string{"a"},
		},
		{
			name:    "key must be a literal",
			cfg:     AppsecConfig{PreEval: []Hook{{Apply: []string{`RateLimit(req.URL.Path, "1/m")`}}}},
			wantErr: "key must be a string literal",
		},
		{
			name:    "limit must be a literal",
			cfg:     AppsecConfig{PreEval: []Hook{{Apply: []string{`RateLimit("a", "1/" + "m")`}}}},
			wantErr: "limit must be a string literal",
		},
		{
			name:    "invalid limit",
			cfg:     AppsecConfig{PreEval: []Hook{{Apply: []string{`RateLimit("a", "1/5m")`}}}},
			wantErr: "unit must be s, m or h",
		},
		{
			name:    "empty key",
			cfg:     AppsecConfig{PreEval: []Hook{{Apply: []string{`RateLimit("", "1/m")`}}}},
			wantErr: "key must not be empty",
		},
		{
			name:    "duplicate key in one hook",
			cfg:     AppsecConfig{PreEval: []Hook{{Filter: `RateLimit("a", "1/m")`, Apply: []string{`RateLimit("a", "1/m")`}}}},
			wantErr: "key is used by more than one call",
		},
		{
			name: "duplicate key across sections",
			cfg: AppsecConfig{
				PreEval: []Hook{{Apply: []string{`RateLimit("a", "1/m")`}}},
				InBand:  &AppsecPhaseConfig{PreEval: []Hook{{Apply: []string{`RateLimit("a", "5/h")`}}}},
			},
			wantErr: "key is used by more than one call",
		},
		{
			name:    "too many arguments",
			cfg:     AppsecConfig{PreEval: []Hook{{Apply: []string{`RateLimit("a", "1/m", "x", "y")`}}}},
			wantErr: "too many arguments to call RateLimit",
		},
		{
			name:    "not available in post_eval",
			cfg:     AppsecConfig{PostEval: []Hook{{Apply: []string{`RateLimit("a", "1/m")`}}}},
			wantErr: "unknown name RateLimit",
		},
		{
			name:    "not available in on_match",
			cfg:     AppsecConfig{OnMatch: []Hook{{Apply: []string{`RateLimit("a", "1/m")`}}}},
			wantErr: "unknown name RateLimit",
		},
		{
			name:    "not available in on_load",
			cfg:     AppsecConfig{OnLoad: []Hook{{Apply: []string{`RateLimit("a", "1/m")`}}}},
			wantErr: "unknown name RateLimit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Logger = log.NewEntry(log.New())

			rt, err := tc.cfg.Build(t.Context(), &cwhub.Hub{})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, rt.RateLimits.limiters, len(tc.wantKeys))

			for _, k := range tc.wantKeys {
				require.NotNil(t, rt.RateLimits.get(k))
			}
		})
	}
}
