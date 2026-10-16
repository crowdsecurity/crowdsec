package appsec

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

func TestAppsecConfigBuildDetectsRequireValidChallenge(t *testing.T) {
	logger := log.New()
	logger.SetOutput(io.Discard)

	// SendChallenge is only exposed in post_eval / on_challenge envs; the patcher
	// detects it from any stage and flags NeedWASMVM.
	cfg := AppsecConfig{
		Logger: log.NewEntry(logger),
		PostEval: []Hook{
			{
				Apply: []string{"SendChallenge()"},
			},
		},
	}

	runtimeCfg, err := cfg.Build(t.Context(), nil)
	require.NoError(t, err)
	assert.True(t, runtimeCfg.NeedWASMVM)
}

func TestAppsecConfigBuildDoesNotDetectRequireValidChallengeWhenUnused(t *testing.T) {
	logger := log.New()
	logger.SetOutput(io.Discard)

	cfg := AppsecConfig{
		Logger: log.NewEntry(logger),
		PreEval: []Hook{
			{
				Apply: []string{"SetRemediation(\"ban\")"},
			},
		},
	}

	runtimeCfg, err := cfg.Build(t.Context(), nil)
	require.NoError(t, err)
	assert.False(t, runtimeCfg.NeedWASMVM)
}

func TestAppsecConfigBuildDetectsHasValidChallengeCookie(t *testing.T) {
	logger := log.New()
	logger.SetOutput(io.Discard)

	cfg := AppsecConfig{
		Logger: log.NewEntry(logger),
		PreEval: []Hook{
			{
				Filter: "HasValidChallengeCookie()",
				Apply:  []string{"SetRemediation(\"allow\")"},
			},
		},
	}

	runtimeCfg, err := cfg.Build(t.Context(), nil)
	require.NoError(t, err)
	assert.True(t, runtimeCfg.NeedWASMVM)
}

func TestAppsecConfigBuildDetectsChallengeInsideMacro(t *testing.T) {
	logger := log.New()
	logger.SetOutput(io.Discard)

	// local macro item, no index entry needed
	dir := t.TempDir()
	local := &csconfig.LocalHubCfg{
		HubDir:       filepath.Join(dir, "hub"),
		HubIndexFile: filepath.Join(dir, "hub", ".index.json"),
		InstallDir:   filepath.Join(dir, "install"),
	}
	require.NoError(t, os.MkdirAll(local.HubDir, 0o700))
	require.NoError(t, os.WriteFile(local.HubIndexFile, []byte("{}"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(local.InstallDir, cwhub.MACROS), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(local.InstallDir, cwhub.MACROS, "m.yaml"), []byte("macros: {Challenge: SendChallenge()}"), 0o600))

	hub, err := cwhub.NewHub(local, nil)
	require.NoError(t, err)
	require.NoError(t, hub.Load())

	_, err = exprhelpers.LoadMacros(hub)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := exprhelpers.LoadMacros(nil)
		require.NoError(t, err)
	})

	cfg := AppsecConfig{
		Logger: log.NewEntry(logger),
		PostEval: []Hook{
			{
				Apply: []string{"Challenge()"},
			},
		},
	}

	runtimeCfg, err := cfg.Build(t.Context(), nil)
	require.NoError(t, err)
	assert.True(t, runtimeCfg.NeedWASMVM)
}
