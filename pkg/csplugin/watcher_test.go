package csplugin

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func stopWatcher(t *testing.T, cancel context.CancelFunc, pw *PluginWatcher, done <-chan struct{}) {
	cancel()

	select {
	case <-pw.PluginEvents:
	case <-time.After(time.Second):
		require.FailNow(t, "timeout waiting for watcher flush event")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "timeout waiting for watcher shutdown")
	}
}

func resetWatcherAlertCounter(pw *PluginWatcher) {
	pw.AlertCountByPluginName.Lock()
	for k := range pw.AlertCountByPluginName.data {
		pw.AlertCountByPluginName.data[k] = 0
	}
	pw.AlertCountByPluginName.Unlock()
}

func insertNAlertsToPlugin(pw *PluginWatcher, n int, pluginName string) {
	for range n {
		pw.Inserts <- pluginName
	}
}

func listenChannelWithTimeout(ctx context.Context, channel chan string) error {
	select {
	case x := <-channel:
		log.Printf("received -> %v", x)
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func TestPluginWatcherInterval(t *testing.T) {
	cstest.SkipOnWindowsBecause(t, "timing is not reliable")

	ctx := t.Context()

	pw := PluginWatcher{}
	alertsByPluginName := make(map[string][]*models.Alert)
	watcherCtx, cancelWatcher := context.WithCancel(ctx)
	configs := map[string]PluginConfig{
		"testPlugin": {
			GroupWait: time.Millisecond,
		},
	}
	pw.Init(configs, alertsByPluginName)
	watcherDone := pw.Start(watcherCtx)

	ct, cancel := context.WithTimeout(ctx, time.Microsecond)
	defer cancel()

	err := listenChannelWithTimeout(ct, pw.PluginEvents)
	cstest.RequireErrorContains(t, err, "context deadline exceeded")
	stopWatcher(t, cancelWatcher, &pw, watcherDone)

	watcherCtx, cancelWatcher = context.WithCancel(ctx)
	watcherDone = pw.Start(watcherCtx)
	insertNAlertsToPlugin(&pw, 1, "testPlugin")

	ct, cancel = context.WithTimeout(ctx, time.Millisecond*5)
	defer cancel()

	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	require.NoError(t, err)
	stopWatcher(t, cancelWatcher, &pw, watcherDone)
	// This is to avoid the int complaining
}

func TestPluginAlertCountWatcher(t *testing.T) {
	cstest.SkipOnWindowsBecause(t, "timing is not reliable")

	ctx := t.Context()

	pw := PluginWatcher{}
	alertsByPluginName := make(map[string][]*models.Alert)
	configs := map[string]PluginConfig{
		"testPlugin": {
			GroupThreshold: 5,
		},
	}
	watcherCtx, cancelWatcher := context.WithCancel(ctx)

	pw.Init(configs, alertsByPluginName)
	watcherDone := pw.Start(watcherCtx)

	// Channel won't contain any events since threshold is not crossed.
	ct, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	err := listenChannelWithTimeout(ct, pw.PluginEvents)
	cstest.RequireErrorContains(t, err, "context deadline exceeded")

	// Channel won't contain any events since threshold is not crossed.
	resetWatcherAlertCounter(&pw)
	insertNAlertsToPlugin(&pw, 4, "testPlugin")

	ct, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()

	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	cstest.RequireErrorContains(t, err, "context deadline exceeded")

	// Channel will contain an event since threshold is crossed.
	resetWatcherAlertCounter(&pw)
	insertNAlertsToPlugin(&pw, 5, "testPlugin")

	ct, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()

	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	require.NoError(t, err)
	stopWatcher(t, cancelWatcher, &pw, watcherDone)
}
