package fileacquisition

import (
	"testing"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func TestConfigureCatModeDoesNotCreateWatcher(t *testing.T) {
	ctx := t.Context()
	f := &Source{}

	err := f.Configure(ctx, []byte(`
mode: cat
filename: testdata/test.log
`), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	assert.Nil(t, f.watcher)
}

func TestConfigureClosesWatcherOnTailModeError(t *testing.T) {
	ctx := t.Context()
	f := &Source{}

	probe, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("cannot allocate fsnotify watcher in this environment: %v", err)
	}

	require.NoError(t, probe.Close())

	err = f.Configure(ctx, []byte(`
mode: tail
filename: "[*-.log"
`), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
	require.ErrorContains(t, err, "glob failure: syntax error in pattern")

	assert.Nil(t, f.watcher)
}
