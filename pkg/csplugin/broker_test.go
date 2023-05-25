//go:build linux || freebsd || netbsd || openbsd || solaris || !windows

package csplugin

import (
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
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

func setPluginPermTo744(t *testing.T) {
	setPluginPermTo(t, "744")
}

func setPluginPermTo722(t *testing.T) {
	setPluginPermTo(t, "722")
}

func setPluginPermTo724(t *testing.T) {
	setPluginPermTo(t, "724")
}
func TestGetPluginNameAndTypeFromPath(t *testing.T) {
	setUp(t)
	defer tearDown(t)
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		expectedErr string
	}{
		{
			name: "valid plugin name, single dash",
			args: args{
				path: path.Join(testPath, "notification-gitter"),
			},
			want:    "notification",
			want1:   "gitter",
		},
		{
			name: "invalid plugin name",
			args: args{
				path: "./tests/gitter",
			},
			expectedErr: "plugin name ./tests/gitter is invalid. Name should be like {type-name}",
		},
		{
			name: "valid plugin name, multiple dash",
			args: args{
				path: "./tests/notification-instant-slack",
			},
			want:    "notification-instant",
			want1:   "slack",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, got1, err := getPluginTypeAndSubtypeFromPath(tc.args.path)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want1, got1)
		})
	}
}

func TestListFilesAtPath(t *testing.T) {
	setUp(t)
	defer tearDown(t)
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		expectedErr string
	}{
		{
			name: "valid directory",
			args: args{
				path: testPath,
			},
			want: []string{
				filepath.Join(testPath, "notification-gitter"),
				filepath.Join(testPath, "slack"),
			},
		},
		{
			name: "invalid directory",
			args: args{
				path: "./foo/bar/",
			},
			expectedErr: "open ./foo/bar/: " + cstest.FileNotFoundMessage,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := listFilesAtPath(tc.args.path)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("listFilesAtPath() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBrokerInit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}

	tests := []struct {
		name        string
		action      func(*testing.T)
		procCfg     csconfig.PluginCfg
		expectedErr string
	}{
		{
			name:   "valid config",
			action: setPluginPermTo744,
		},
		{
			name:        "group writable binary",
			expectedErr: "notification-dummy is world writable",
			action:      setPluginPermTo722,
		},
		{
			name:        "group writable binary",
			expectedErr: "notification-dummy is group writable",
			action:      setPluginPermTo724,
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
				err := os.Remove(path.Join(testPath, "notification-dummy"))
				require.NoError(t, err)
			},
		},
		{
			name:        "only specify user",
			expectedErr: "both plugin user and group must be set",
			procCfg: csconfig.PluginCfg{
				User: "123445555551122toto",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "only specify group",
			expectedErr: "both plugin user and group must be set",
			procCfg: csconfig.PluginCfg{
				Group: "123445555551122toto",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "Fails to run as root",
			expectedErr: "operation not permitted",
			procCfg: csconfig.PluginCfg{
				User:  "root",
				Group: "root",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "Invalid user and group",
			expectedErr: "unknown user toto1234",
			procCfg: csconfig.PluginCfg{
				User:  "toto1234",
				Group: "toto1234",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "Valid user and invalid group",
			expectedErr: "unknown group toto1234",
			procCfg: csconfig.PluginCfg{
				User:  "nobody",
				Group: "toto1234",
			},
			action: setPluginPermTo744,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			defer tearDown(t)
			buildDummyPlugin(t)
			if tc.action != nil {
				tc.action(t)
			}
			pb := PluginBroker{}
			profiles := csconfig.NewDefaultConfig().API.Server.Profiles
			profiles = append(profiles, &csconfig.ProfileCfg{
				Notifications: []string{"dummy_default"},
			})
			err := pb.Init(&tc.procCfg, profiles, &csconfig.ConfigurationPaths{
				PluginDir:       testPath,
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
	setPluginPermTo744(t)
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
		PluginDir:       testPath,
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
	setPluginPermTo744(t)
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
		PluginDir:       testPath,
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
	setPluginPermTo(t, "744")
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
		PluginDir:       testPath,
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
	setPluginPermTo(t, "744")
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
		PluginDir:       testPath,
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
	setPluginPermTo(t, "744")
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
		PluginDir:       testPath,
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
	setPluginPermTo(t, "744")
	defer tearDown(t)
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       testPath,
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
	dir, err := os.MkdirTemp("./tests", "cs_plugin_test")
	require.NoError(t, err)

	cmd := exec.Command("go", "build", "-o", path.Join(dir, "notification-dummy"), "../../plugins/notifications/dummy/")
	err = cmd.Run()
	require.NoError(t, err, "while building dummy plugin")

	testPath = dir
	os.Remove("./out")
}

func setPluginPermTo(t *testing.T, perm string) {
	if runtime.GOOS != "windows" {
		err := exec.Command("chmod", perm, path.Join(testPath, "notification-dummy")).Run()
		require.NoError(t, err, "chmod 744 %s", path.Join(testPath, "notification-dummy"))
	}
}

func setUp(t *testing.T) {
	dir, err := os.MkdirTemp("./", "cs_plugin_test")
	require.NoError(t, err)

	f, err := os.Create(path.Join(dir, "slack"))
	require.NoError(t, err)

	f.Close()
	f, err = os.Create(path.Join(dir, "notification-gitter"))
	require.NoError(t, err)

	f.Close()
	err = os.Mkdir(path.Join(dir, "dummy_dir"), 0666)
	require.NoError(t, err)

	testPath = dir
}

func tearDown(t *testing.T) {
	err := os.RemoveAll(testPath)
	require.NoError(t, err)

	os.Remove("./out")
}
