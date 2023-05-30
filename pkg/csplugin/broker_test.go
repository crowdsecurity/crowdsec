//go:build linux || freebsd || netbsd || openbsd || solaris || !windows

package csplugin

import (
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var testPath string
var binPath string

func pluginBinary() string {
	binPath = path.Join(testPath, "bin")
	return path.Join(binPath, "notification-dummy")
}

func pluginConfig() string {
	return path.Join(testPath, "config", "dummy.yaml")
}

func TestBrokerInit(t *testing.T) {
	tests := []struct {
		name        string
		action      func(*testing.T)
		procCfg     csconfig.PluginCfg
		expectedErr string
	}{
		{
			name:   "valid config",
		},
		{
			name:        "group writable binary",
			expectedErr: "notification-dummy is world writable",
			action:      permissionSetter(0o722),
		},
		{
			name:        "group writable binary",
			expectedErr: "notification-dummy is group writable",
			action:      permissionSetter(0o724),
		},
		{
			name:        "no plugin dir",
			expectedErr: cstest.FileNotFoundMessage,
			action:      tearDown,
		},
		{
			name:        "no plugin binary",
			expectedErr: "binary for plugin dummy_default not found",
			action: func(t *testing.T) {
				err := os.Remove(pluginBinary())
				require.NoError(t, err)
			},
		},
		{
			name:        "only specify user",
			expectedErr: "both plugin user and group must be set",
			procCfg: csconfig.PluginCfg{
				User: "123445555551122toto",
			},
		},
		{
			name:        "only specify group",
			expectedErr: "both plugin user and group must be set",
			procCfg: csconfig.PluginCfg{
				Group: "123445555551122toto",
			},
		},
		{
			name:        "Fails to run as root",
			expectedErr: "operation not permitted",
			procCfg: csconfig.PluginCfg{
				User:  "root",
				Group: "root",
			},
		},
		{
			name:        "Invalid user and group",
			expectedErr: "unknown user toto1234",
			procCfg: csconfig.PluginCfg{
				User:  "toto1234",
				Group: "toto1234",
			},
		},
		{
			name:        "Valid user and invalid group",
			expectedErr: "unknown group toto1234",
			procCfg: csconfig.PluginCfg{
				User:  "nobody",
				Group: "toto1234",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			defer tearDown(t)
			buildDummyPlugin(t)
			permissionSetter(0o744)(t)
			if tc.action != nil {
				tc.action(t)
			}
			pb := PluginBroker{}
			profiles := csconfig.NewDefaultConfig().API.Server.Profiles
			profiles = append(profiles, &csconfig.ProfileCfg{
				Notifications: []string{"dummy_default"},
			})
			err := pb.Init(&tc.procCfg, profiles, &csconfig.ConfigurationPaths{
				PluginDir:       binPath,
				NotificationDir: "./tests/notifications",
			})
			defer pb.Kill()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func readconfig(t *testing.T, path string) ([]byte, PluginConfig) {
	var config PluginConfig
	orig, err := os.ReadFile("tests/notifications/dummy.yaml")
	require.NoError(t, err,"unable to read config file %s", path)

	err = yaml.Unmarshal(orig, &config)
	require.NoError(t, err,"unable to unmarshal config file")
	
	return orig, config
}

func writeconfig(t *testing.T, config PluginConfig, path string) {
	data, err := yaml.Marshal(&config)
	require.NoError(t, err,"unable to marshal config file")

	err = os.WriteFile(path, data, 0644)
	require.NoError(t, err,"unable to write config file %s", path)
}

func TestBrokerNoThreshold(t *testing.T) {
	var alerts []models.Alert
	DefaultEmptyTicker = 50 * time.Millisecond

	buildDummyPlugin(t)
	defer tearDown(t)

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// default config
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       binPath,
		NotificationDir: "./tests/notifications",
	})

	assert.NoError(t, err)
	tomb := tomb.Tomb{}

	go pb.Run(&tomb)
	defer pb.Kill()

	// send one item, it should be processed right now
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(200 * time.Millisecond)

	// we expect one now
	content, err := os.ReadFile("./out")
	require.NoError(t, err, "Error reading file")

	err = json.Unmarshal(content, &alerts)
	assert.NoError(t, err)
	assert.Len(t, alerts, 1)

	// remove it
	os.Remove("./out")

	// and another one
	log.Printf("second send")
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(200 * time.Millisecond)

	// we expect one again, as we cleaned the file
	content, err = os.ReadFile("./out")
	require.NoError(t, err, "Error reading file")

	err = json.Unmarshal(content, &alerts)
	log.Printf("content-> %s", content)
	assert.NoError(t, err)
	assert.Len(t, alerts, 1)
}

func TestBrokerRunGroupAndTimeThreshold_TimeFirst(t *testing.T) {
	// test grouping by "time"
	DefaultEmptyTicker = 50 * time.Millisecond
	buildDummyPlugin(t)
	defer tearDown(t)

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	// set groupwait and groupthreshold, should honor whichever comes first
	raw, cfg := readconfig(t, "tests/notifications/dummy.yaml")
	cfg.GroupThreshold = 4
	cfg.GroupWait = 1 * time.Second
	writeconfig(t, cfg, "tests/notifications/dummy.yaml")
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       binPath,
		NotificationDir: "./tests/notifications",
	})
	assert.NoError(t, err)
	tomb := tomb.Tomb{}

	go pb.Run(&tomb)
	defer pb.Kill()
	// send data
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(500 * time.Millisecond)
	// because of group threshold, we shouldn't have data yet
	assert.NoFileExists(t, "./out")
	time.Sleep(1 * time.Second)
	// after 1 seconds, we should have data
	content, err := os.ReadFile("./out")
	assert.NoError(t, err)

	var alerts []models.Alert
	err = json.Unmarshal(content, &alerts)
	assert.NoError(t, err)
	assert.Len(t, alerts, 3)

	// restore config
	err = os.WriteFile("tests/notifications/dummy.yaml", raw, 0644)
	require.NoError(t, err,"unable to write config file")
}

func TestBrokerRunGroupAndTimeThreshold_CountFirst(t *testing.T) {
	DefaultEmptyTicker = 50 * time.Millisecond
	buildDummyPlugin(t)
	defer tearDown(t)

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// set groupwait and groupthreshold, should honor whichever comes first
	raw, cfg := readconfig(t, "tests/notifications/dummy.yaml")
	cfg.GroupThreshold = 4
	cfg.GroupWait = 4 * time.Second
	writeconfig(t, cfg, "tests/notifications/dummy.yaml")
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       binPath,
		NotificationDir: "./tests/notifications",
	})
	assert.NoError(t, err)
	tomb := tomb.Tomb{}

	go pb.Run(&tomb)
	defer pb.Kill()

	// send data
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(100 * time.Millisecond)

	// because of group threshold, we shouldn't have data yet
	assert.NoFileExists(t, "./out")
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(100 * time.Millisecond)

	// and now we should
	content, err := os.ReadFile("./out")
	require.NoError(t, err, "Error reading file")

	var alerts []models.Alert
	err = json.Unmarshal(content, &alerts)
	assert.NoError(t, err)
	assert.Len(t, alerts, 4)

	// restore config
	err = os.WriteFile("tests/notifications/dummy.yaml", raw, 0644)
	require.NoError(t, err,"unable to write config file")
}

func TestBrokerRunGroupThreshold(t *testing.T) {
	// test grouping by "size"
	DefaultEmptyTicker = 50 * time.Millisecond
	buildDummyPlugin(t)
	defer tearDown(t)

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// set groupwait
	raw, cfg := readconfig(t, "tests/notifications/dummy.yaml")
	cfg.GroupThreshold = 4
	writeconfig(t, cfg, "tests/notifications/dummy.yaml")
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       binPath,
		NotificationDir: "./tests/notifications",
	})

	assert.NoError(t, err)
	tomb := tomb.Tomb{}

	go pb.Run(&tomb)
	defer pb.Kill()

	// send data
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(100 * time.Millisecond)

	// because of group threshold, we shouldn't have data yet
	assert.NoFileExists(t, "./out")
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(100 * time.Millisecond)

	// and now we should
	content, err := os.ReadFile("./out")
	require.NoError(t, err, "Error reading file")

	var alerts []models.Alert
	err = json.Unmarshal(content, &alerts)
	assert.NoError(t, err)
	assert.Len(t, alerts, 4)

	// restore config
	err = os.WriteFile("tests/notifications/dummy.yaml", raw, 0644)
	require.NoError(t, err, "unable to write config file")
}

func TestBrokerRunTimeThreshold(t *testing.T) {
	DefaultEmptyTicker = 50 * time.Millisecond
	buildDummyPlugin(t)
	defer tearDown(t)

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// set groupwait
	raw, cfg := readconfig(t, "tests/notifications/dummy.yaml")
	cfg.GroupWait = 1 * time.Second
	writeconfig(t, cfg, "tests/notifications/dummy.yaml")
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       binPath,
		NotificationDir: "./tests/notifications",
	})
	assert.NoError(t, err)
	tomb := tomb.Tomb{}

	go pb.Run(&tomb)
	defer pb.Kill()

	// send data
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(200 * time.Millisecond)

	// we shouldn't have data yet
	assert.NoFileExists(t, "./out")
	time.Sleep(1 * time.Second)

	// and now we should
	content, err := os.ReadFile("./out")
	require.NoError(t, err, "Error reading file")

	var alerts []models.Alert
	err = json.Unmarshal(content, &alerts)
	assert.NoError(t, err)
	assert.Len(t, alerts, 1)

	// restore config
	err = os.WriteFile("tests/notifications/dummy.yaml", raw, 0644)
	require.NoError(t, err, "unable to write config file %s", err)
}

func TestBrokerRunSimple(t *testing.T) {
	DefaultEmptyTicker = 50 * time.Millisecond
	buildDummyPlugin(t)
	defer tearDown(t)
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       binPath,
		NotificationDir: "./tests/notifications",
	})
	assert.NoError(t, err)
	tomb := tomb.Tomb{}

	go pb.Run(&tomb)
	defer pb.Kill()

	assert.NoFileExists(t, "./out")

	defer os.Remove("./out")

	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(time.Millisecond * 200)

	content, err := os.ReadFile("./out")
	require.NoError(t, err, "Error reading file")

	var alerts []models.Alert
	err = json.Unmarshal(content, &alerts)
	assert.NoError(t, err)
	assert.Len(t, alerts, 2)
}

func buildDummyPlugin(t *testing.T) {
	var err error

	testPath, err = os.MkdirTemp("", "cs_plugin_test")
	require.NoError(t, err)

	// create bin, config directories
	
	err = os.MkdirAll(path.Join(testPath, "config"), 0o755)
	require.NoError(t, err, "while creating config dir")

	err = os.MkdirAll(path.Join(testPath, "bin"), 0o755)
	require.NoError(t, err, "while creating bin dir")
	
	cmd := exec.Command("go", "build", "-o", pluginBinary(), "../../plugins/notifications/dummy/")
	err = cmd.Run()
	require.NoError(t, err, "while building dummy plugin")

	err = os.Chmod(pluginBinary(), 0o744)
	require.NoError(t, err, "chmod 0744 %s", pluginBinary)

	os.Remove("./out")
}

func permissionSetter(perm os.FileMode) func(*testing.T) {
	// temporarily change permissions, and restore them after the test
	return func(t *testing.T) {
		err := os.Chmod(pluginBinary(), perm)
		require.NoError(t, err, "chmod %s %s", perm, pluginBinary())
	}
}

func tearDown(t *testing.T) {
	err := os.RemoveAll(testPath)
	require.NoError(t, err)

	os.Remove("./out")
}
