package appsec

import (
	"io"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
