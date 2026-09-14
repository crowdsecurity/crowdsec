package appsecacquisition

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// hubWithConfigs builds an in-memory hub holding the given appsec-configs and
// marks the listed ones as installed (an installed item is one with a
// LocalPath, see cwhub.ItemState.IsInstalled).
func hubWithConfigs(t *testing.T, all, installed []string) *cwhub.Hub {
	t.Helper()

	tempDir := t.TempDir()
	local := &csconfig.LocalHubCfg{
		HubDir:         filepath.Join(tempDir, "hub"),
		HubIndexFile:   filepath.Join(tempDir, "hub", ".index.json"),
		InstallDir:     filepath.Join(tempDir, "install"),
		InstallDataDir: filepath.Join(tempDir, "data"),
	}

	require.NoError(t, os.MkdirAll(local.HubDir, 0o755))
	require.NoError(t, os.MkdirAll(local.InstallDir, 0o755))
	require.NoError(t, os.MkdirAll(local.InstallDataDir, 0o755))

	index := `{"appsec-configs": {`
	for i, name := range all {
		if i > 0 {
			index += ","
		}
		index += `"` + name + `": {"path": "appsec-configs/` + name + `.yaml", "version": "1.0", "versions": {"1.0": {"digest": "aa"}}}`
	}
	index += "}}"

	require.NoError(t, os.WriteFile(local.HubIndexFile, []byte(index), 0o644))

	hub, err := cwhub.NewHub(local, nil)
	require.NoError(t, err)
	require.NoError(t, hub.Load())

	for _, name := range installed {
		item := hub.GetItem(cwhub.APPSEC_CONFIGS, name)
		require.NotNilf(t, item, "appsec-config %q missing from test hub", name)
		item.State.LocalPath = filepath.Join(local.InstallDir, name+".yaml")
	}

	return hub
}

// authTestSource builds a Source with just enough wiring to exercise checkAuth:
// a LAPI URL pointing at a test server and a client bounded by authTimeout.
func authTestSource(t *testing.T, lapiURL string, authTimeout time.Duration) *Source {
	t.Helper()

	logger := log.New()
	logger.SetOutput(io.Discard)

	return &Source{
		logger:     log.NewEntry(logger),
		lapiURL:    lapiURL,
		AuthCache:  NewAuthCache(),
		httpClient: &http.Client{Timeout: authTimeout},
		config: Configuration{
			AuthCacheDuration: ptr.Of(time.Minute),
			AuthTimeout:       &authTimeout,
		},
	}
}

func TestCheckAuth(t *testing.T) {
	const (
		apiKey      = "test-key"
		authTimeout = 100 * time.Millisecond
		slowLAPI    = 300 * time.Millisecond
	)

	tests := []struct {
		name string
		key  string
		// cachedFor, when set, seeds the auth cache with an expiry at now+cachedFor.
		cachedFor    *time.Duration
		status       int
		delay        time.Duration
		expectedErr  error
		expectedHits int64
		// stillCached asserts the key is present and unexpired afterwards.
		stillCached bool
	}{
		{
			name:        "empty key is rejected without contacting lapi",
			key:         "",
			expectedErr: errMissingAPIKey,
		},
		{
			name:         "cold cache, lapi accepts the key",
			key:          apiKey,
			status:       http.StatusOK,
			expectedHits: 1,
			stillCached:  true,
		},
		{
			name:         "cold cache, lapi rejects the key",
			key:          apiKey,
			status:       http.StatusForbidden,
			expectedErr:  errInvalidAPIKey,
			expectedHits: 1,
		},
		{
			// The case reported in #4584: with nothing cached there is no key to
			// fall back on, so a LAPI slower than auth_timeout 401s the bouncer.
			name:         "cold cache, lapi slower than auth_timeout",
			key:          apiKey,
			status:       http.StatusOK,
			delay:        slowLAPI,
			expectedErr:  errInvalidAPIKey,
			expectedHits: 1,
		},
		{
			name:        "unexpired cache entry is served without contacting lapi",
			key:         apiKey,
			cachedFor:   ptr.Of(time.Minute),
			status:      http.StatusOK,
			stillCached: true,
		},
		{
			// Fail open: we already knew this key, don't break traffic because
			// LAPI is unreachable.
			name:         "expired cache entry, lapi unreachable, key is kept",
			key:          apiKey,
			cachedFor:    ptr.Of(-time.Minute),
			status:       http.StatusOK,
			delay:        slowLAPI,
			expectedHits: 1,
			stillCached:  true,
		},
		{
			name:         "expired cache entry, key revoked, evicted from cache",
			key:          apiKey,
			cachedFor:    ptr.Of(-time.Minute),
			status:       http.StatusForbidden,
			expectedErr:  errInvalidAPIKey,
			expectedHits: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64

			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				time.Sleep(tc.delay)
				rw.WriteHeader(tc.status)
			}))
			defer srv.Close()

			w := authTestSource(t, srv.URL, authTimeout)

			if tc.cachedFor != nil {
				w.AuthCache.Set(apiKey, time.Now().Add(*tc.cachedFor))
			}

			err := w.checkAuth(t.Context(), tc.key)
			require.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedHits, hits.Load())

			expiration, exists := w.AuthCache.Get(apiKey)
			if !tc.stillCached {
				assert.False(t, exists, "key should not be cached")
				return
			}

			require.True(t, exists, "key should be cached")
			assert.True(t, expiration.After(time.Now()), "cached key should not be expired")
		})
	}
}

func TestCheckAuthSharesProbeForSameKey(t *testing.T) {
	const routines = 20

	var (
		hits    atomic.Int64
		entered atomic.Int64
	)

	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-release
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := authTestSource(t, srv.URL, 5*time.Second)

	var wg sync.WaitGroup

	errs := make([]error, routines)

	for i := range routines {
		wg.Go(func() {
			entered.Add(1)
			errs[i] = w.checkAuth(t.Context(), "test-key")
		})
	}

	// The handler is held open, so every goroutine that reaches checkAuth before
	// we release it must join the in-flight probe rather than start its own.
	require.Eventually(t, func() bool { return entered.Load() == routines }, time.Second, time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	close(release)

	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(1), hits.Load(), "concurrent checks for the same key should share a single LAPI probe")
}

func TestCheckAuthDoesNotSerializeDistinctKeys(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := authTestSource(t, srv.URL, 5*time.Second)

	var wg sync.WaitGroup

	for _, key := range []string{"key-a", "key-b"} {
		wg.Go(func() {
			assert.NoError(t, w.checkAuth(t.Context(), key))
		})
	}

	// Neither probe can return before we release, so seeing both start proves
	// they run concurrently instead of queueing behind a process-wide lock.
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			wg.Wait()
			t.Fatal("second LAPI probe never started: auth checks for distinct keys are serialized")
		}
	}

	close(release)
	wg.Wait()
}

func TestUnmarshalConfigAuthTimeout(t *testing.T) {
	const base = "source: appsec\nappsec_config: crowdsecurity/vpatch\n"

	tests := []struct {
		name     string
		config   string
		expected *time.Duration
	}{
		{
			name:     "auth_timeout is parsed as a duration",
			config:   base + "auth_timeout: 2s\n",
			expected: ptr.Of(2 * time.Second),
		},
		{
			name:     "auth_timeout can be disabled with 0",
			config:   base + "auth_timeout: 0s\n",
			expected: ptr.Of(time.Duration(0)),
		},
		{
			// Left nil here, Configure applies DefaultAuthTimeout.
			name:     "auth_timeout is optional",
			config:   base,
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &Source{}
			require.NoError(t, w.UnmarshalConfig([]byte(tc.config)))
			assert.Equal(t, tc.expected, w.config.AuthTimeout)
		})
	}
}

func TestExpandAppsecConfigEntry(t *testing.T) {
	all := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "crowdsecurity/uninstalled", "custom/mine"}
	installed := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "custom/mine"}

	tests := []struct {
		name        string
		entry       string
		expected    []string
		expectedErr string
	}{
		{
			// Literals pass through untouched, even unknown ones, so the
			// per-name error still surfaces later from AppsecConfig.Load.
			name:     "literal passthrough",
			entry:    "crowdsecurity/vpatch",
			expected: []string{"crowdsecurity/vpatch"},
		},
		{
			name:     "unknown literal passthrough",
			entry:    "does/not-exist",
			expected: []string{"does/not-exist"},
		},
		{
			// Sorted (case-insensitive) order from the hub; uninstalled is skipped.
			name:     "wildcard expands installed only",
			entry:    "crowdsecurity/*",
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch"},
		},
		{
			name:     "wildcard matches all",
			entry:    "*",
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch", "custom/mine"},
		},
		{
			name:        "wildcard with no match errors",
			entry:       "nope/*",
			expectedErr: `no installed appsec-config matches pattern "nope/*"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hub := hubWithConfigs(t, all, installed)

			got, err := expandAppsecConfigEntry(tc.entry, hub)
			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestResolveAppsecConfigEntries(t *testing.T) {
	all := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "crowdsecurity/uninstalled", "custom/mine"}
	installed := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "custom/mine"}

	tests := []struct {
		name     string
		entries  []string
		expected []string
	}{
		{
			// "*" already pulls in vpatch; the explicit literal must not load it
			// a second time. First-seen order from the wildcard expansion wins.
			name:     "wildcard plus overlapping literal dedups",
			entries:  []string{"*", "crowdsecurity/vpatch"},
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch", "custom/mine"},
		},
		{
			name:     "same literal twice collapses to one",
			entries:  []string{"crowdsecurity/vpatch", "crowdsecurity/vpatch"},
			expected: []string{"crowdsecurity/vpatch"},
		},
		{
			name:     "unknown literal passes through once",
			entries:  []string{"does/not-exist", "does/not-exist"},
			expected: []string{"does/not-exist"},
		},
		{
			// Overlapping patterns: generic matches both, must appear once.
			name:     "overlapping patterns dedup",
			entries:  []string{"crowdsecurity/*", "*/generic"},
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hub := hubWithConfigs(t, all, installed)

			got, err := resolveAppsecConfigEntries(tc.entries, hub)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}
