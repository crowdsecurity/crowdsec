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

	cfg := AppsecConfig{
		Logger: log.NewEntry(logger),
		PreEval: []Hook{
			{
				Apply: []string{"RequireValidChallenge()"},
			},
		},
	}

	runtimeCfg, err := cfg.Build(nil)
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

	runtimeCfg, err := cfg.Build(nil)
	require.NoError(t, err)
	assert.False(t, runtimeCfg.NeedWASMVM)
}
