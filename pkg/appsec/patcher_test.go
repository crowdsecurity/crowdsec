package appsec

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "m.yaml"), []byte("Challenge: SendChallenge()"), 0o600))
	require.NoError(t, exprhelpers.LoadMacros(dir))
	t.Cleanup(func() { require.NoError(t, exprhelpers.LoadMacros("")) })

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
