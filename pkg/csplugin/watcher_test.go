package csplugin

import (
	"context"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"gopkg.in/tomb.v2"
	"gotest.tools/v3/assert"
)

var ctx = context.Background()
var testTomb = tomb.Tomb{}

func resetTestTomb() {
	testTomb.Kill(nil)
	testTomb.Wait()
	testTomb = tomb.Tomb{}
}

func resetWatcherAlertCounter(pw *PluginWatcher) {
	for k := range pw.AlertCountByPluginName {
		pw.AlertCountByPluginName[k] = 0
	}
}

func insertNAlertsToPlugin(pw *PluginWatcher, n int, pluginName string) {
	for i := 0; i < n; i++ {
		pw.Inserts <- pluginName
	}
}

func listenChannelWithTimeout(ctx context.Context, channel chan string) error {
	select {
	case <-channel:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func TestPluginWatcherInterval(t *testing.T) {
	pw := PluginWatcher{}
	alertsByPluginName := make(map[string][]*models.Alert)
	configs := map[string]PluginConfig{
		"testPlugin": {
			GroupWait: time.Millisecond,
		},
	}
	pw.Init(configs, alertsByPluginName)
	pw.Start(&testTomb)

	ct, _ := context.WithTimeout(ctx, time.Microsecond)
	err := listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.ErrorContains(t, err, "context deadline exceeded")

	resetTestTomb()
	pw.Start(&testTomb)

	ct, _ = context.WithTimeout(ctx, time.Millisecond)
	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.NilError(t, err)
	resetTestTomb()
}

func TestPluginAlertCountWatcher(t *testing.T) {
	pw := PluginWatcher{}
	alertsByPluginName := make(map[string][]*models.Alert)
	configs := map[string]PluginConfig{
		"testPlugin": {
			GroupThreshold: 5,
		},
	}
	pw.Init(configs, alertsByPluginName)
	pw.Start(&testTomb)

	// Channel won't contain any events since threshold is not crossed.
	ct, _ := context.WithTimeout(ctx, time.Millisecond)
	err := listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.ErrorContains(t, err, "context deadline exceeded")

	// Channel won't contain any events since threshold is not crossed.
	resetWatcherAlertCounter(&pw)
	insertNAlertsToPlugin(&pw, 4, "testPlugin")
	ct, _ = context.WithTimeout(ctx, time.Millisecond)
	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.ErrorContains(t, err, "context deadline exceeded")

	// Channel will contain an event since threshold is crossed.
	resetWatcherAlertCounter(&pw)
	insertNAlertsToPlugin(&pw, 5, "testPlugin")
	ct, _ = context.WithTimeout(ctx, time.Second)
	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.NilError(t, err)

	resetTestTomb()
}
