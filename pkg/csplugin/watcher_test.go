package csplugin

import (
	"context"
	"log"
	"runtime"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"gopkg.in/tomb.v2"
	"gotest.tools/v3/assert"
)

var ctx = context.Background()

func resetTestTomb(testTomb *tomb.Tomb, pw *PluginWatcher) {
	testTomb.Kill(nil)
	<-pw.PluginEvents
	if err := testTomb.Wait(); err != nil {
		log.Fatal(err)
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
	for i := 0; i < n; i++ {
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
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows because timing is not reliable")
	}
	pw := PluginWatcher{}
	alertsByPluginName := make(map[string][]*models.Alert)
	testTomb := tomb.Tomb{}
	configs := map[string]PluginConfig{
		"testPlugin": {
			GroupWait: time.Millisecond,
		},
	}
	pw.Init(configs, alertsByPluginName)
	pw.Start(&testTomb)

	ct, cancel := context.WithTimeout(ctx, time.Microsecond)
	defer cancel()
	err := listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.ErrorContains(t, err, "context deadline exceeded")
	resetTestTomb(&testTomb, &pw)
	testTomb = tomb.Tomb{}
	pw.Start(&testTomb)

	ct, cancel = context.WithTimeout(ctx, time.Millisecond*5)
	defer cancel()
	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.NilError(t, err)
	resetTestTomb(&testTomb, &pw)
	// This is to avoid the int complaining
}

func TestPluginAlertCountWatcher(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows because timing is not reliable")
	}
	pw := PluginWatcher{}
	alertsByPluginName := make(map[string][]*models.Alert)
	configs := map[string]PluginConfig{
		"testPlugin": {
			GroupThreshold: 5,
		},
	}
	testTomb := tomb.Tomb{}
	pw.Init(configs, alertsByPluginName)
	pw.Start(&testTomb)

	// Channel won't contain any events since threshold is not crossed.
	ct, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.ErrorContains(t, err, "context deadline exceeded")

	// Channel won't contain any events since threshold is not crossed.
	resetWatcherAlertCounter(&pw)
	insertNAlertsToPlugin(&pw, 4, "testPlugin")
	ct, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.ErrorContains(t, err, "context deadline exceeded")

	// Channel will contain an event since threshold is crossed.
	resetWatcherAlertCounter(&pw)
	insertNAlertsToPlugin(&pw, 5, "testPlugin")
	ct, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = listenChannelWithTimeout(ct, pw.PluginEvents)
	assert.NilError(t, err)
	resetTestTomb(&testTomb, &pw)
}
