//go:build linux || freebsd || netbsd || openbsd || solaris || !windows

package csplugin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)


type PluginSuite struct {
	suite.Suite

	// where the plugin is built
	buildDir string
	// full path to the built plugin binary
	builtBinary string

	runDir string		// temporary directory for each test
	pluginDir  string		// (config_paths.plugin_dir)
	notifDir string	// (config_paths.notification_dir)
	pluginBinary string	// full path to the plugin binary (unique for each test)
	pluginConfig string	// full path to the notification config (unique for each test)
}


func TestPluginSuite(t *testing.T) {
	suite.Run(t, new(PluginSuite))
}


func (s *PluginSuite) SetupSuite() {
	var err error

	t := s.T()

	s.buildDir, err = os.MkdirTemp("", "cs_plugin_test_build")
	require.NoError(t, err)

	s.builtBinary = path.Join(s.buildDir, "notification-dummy")
	cmd := exec.Command("go", "build", "-o", s.builtBinary, "../../plugins/notifications/dummy/")
	err = cmd.Run()
	require.NoError(t, err, "while building dummy plugin")
}


func (s *PluginSuite) TearDownSuite() {
	t := s.T()
	err := os.RemoveAll(s.buildDir)
	require.NoError(t, err)
}


func copyFile(src string, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)
	if err != nil {
		return err
	}

	err = d.Sync()
	if err != nil {
		return err
	}

	return nil
}

func (s *PluginSuite) SetupTest() {
	s.SetupSubTest()
}

func (s *PluginSuite) TearDownTest() {
	s.TearDownSubTest()
}


func (s *PluginSuite) SetupSubTest() {
	var err error
	t := s.T()

	fmt.Printf("SetupTest %s\n", t.Name())

	s.runDir, err = os.MkdirTemp("", "cs_plugin_test")
	require.NoError(t, err)

	s.pluginDir = path.Join(s.runDir, "bin")
	err = os.MkdirAll(path.Join(s.runDir, "bin"), 0o755)
	require.NoError(t, err, "while creating bin dir")

	s.notifDir = path.Join(s.runDir, "config")
	err = os.MkdirAll(s.notifDir, 0o755)
	require.NoError(t, err, "while creating config dir")

	s.pluginBinary = path.Join(s.pluginDir, "notification-dummy")
	err = copyFile(s.builtBinary, s.pluginBinary)
	require.NoError(t, err, "while copying built binary")
	err = os.Chmod(s.pluginBinary, 0o744)
	require.NoError(t, err, "chmod 0744 %s", s.pluginBinary)
	
	s.pluginConfig = path.Join(s.notifDir, "dummy.yaml")
	err = copyFile("testdata/dummy.yaml", s.pluginConfig)
	require.NoError(t, err, "while copying plugin config")
}

func (s *PluginSuite) TearDownSubTest() {
	t := s.T()
	err := os.RemoveAll(s.runDir)
	require.NoError(t, err)

	os.Remove("./out")
}

func (s *PluginSuite) permissionSetter(perm os.FileMode) func(*testing.T) {
	return func(t *testing.T) {
		err := os.Chmod(s.pluginBinary, perm)
		require.NoError(t, err, "chmod %s %s", perm, s.pluginBinary)
	}
}

func (s *PluginSuite) readconfig() (PluginConfig) {
	var config PluginConfig
	t := s.T()

	orig, err := os.ReadFile(s.pluginConfig)
	require.NoError(t, err,"unable to read config file %s", s.pluginConfig)

	err = yaml.Unmarshal(orig, &config)
	require.NoError(t, err,"unable to unmarshal config file")
	
	return config
}


func (s *PluginSuite) writeconfig(config PluginConfig) {
	t := s.T()
	data, err := yaml.Marshal(&config)
	require.NoError(t, err,"unable to marshal config file")

	err = os.WriteFile(s.pluginConfig, data, 0644)
	require.NoError(t, err,"unable to write config file %s", s.pluginConfig)
}


func (s *PluginSuite) TestBrokerInit() {
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
			action:      s.permissionSetter(0o722),
		},
		{
			name:        "group writable binary",
			expectedErr: "notification-dummy is group writable",
			action:      s.permissionSetter(0o724),
		},
		{
			name:        "no plugin dir",
			expectedErr: cstest.FileNotFoundMessage,
			action: func(t *testing.T) {
				err := os.RemoveAll(s.runDir)
				require.NoError(t, err)
			},
		},
		{
			name:        "no plugin binary",
			expectedErr: "binary for plugin dummy_default not found",
			action: func(t *testing.T) {
				err := os.Remove(s.pluginBinary)
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
		s.Run(tc.name, func() {
			t := s.T()
			if tc.action != nil {
				tc.action(t)
			}
			pb := PluginBroker{}
			profiles := csconfig.NewDefaultConfig().API.Server.Profiles
			profiles = append(profiles, &csconfig.ProfileCfg{
				Notifications: []string{"dummy_default"},
			})
			err := pb.Init(&tc.procCfg, profiles, &csconfig.ConfigurationPaths{
				PluginDir:       s.pluginDir,
				NotificationDir: s.notifDir,
			})
			defer pb.Kill()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func (s *PluginSuite) TestBrokerNoThreshold() {
	var alerts []models.Alert
	DefaultEmptyTicker = 50 * time.Millisecond

	t := s.T()

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// default config
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       s.pluginDir,
		NotificationDir: s.notifDir,
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
	require.NoError(t, err)
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

func (s *PluginSuite) TestBrokerRunGroupAndTimeThreshold_TimeFirst() {
	// test grouping by "time"
	DefaultEmptyTicker = 50 * time.Millisecond

	t := s.T()

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	// set groupwait and groupthreshold, should honor whichever comes first
	cfg := s.readconfig()
	cfg.GroupThreshold = 4
	cfg.GroupWait = 1 * time.Second
	s.writeconfig(cfg)
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       s.pluginDir,
		NotificationDir: s.notifDir,
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
}

func (s *PluginSuite) TestBrokerRunGroupAndTimeThreshold_CountFirst() {
	DefaultEmptyTicker = 50 * time.Millisecond

	t := s.T()

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// set groupwait and groupthreshold, should honor whichever comes first
	cfg := s.readconfig()
	cfg.GroupThreshold = 4
	cfg.GroupWait = 4 * time.Second
	s.writeconfig(cfg)
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       s.pluginDir,
		NotificationDir: s.notifDir,
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
}

func (s *PluginSuite) TestBrokerRunGroupThreshold() {
	// test grouping by "size"
	DefaultEmptyTicker = 50 * time.Millisecond

	t := s.T()

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// set groupwait
	cfg := s.readconfig()
	cfg.GroupThreshold = 4
	s.writeconfig(cfg)
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       s.pluginDir,
		NotificationDir: s.notifDir,
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
}

func (s *PluginSuite) TestBrokerRunTimeThreshold() {
	DefaultEmptyTicker = 50 * time.Millisecond

	t := s.T()

	// init
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})

	// set groupwait
	cfg := s.readconfig()
	cfg.GroupWait = 1 * time.Second
	s.writeconfig(cfg)
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       s.pluginDir,
		NotificationDir: s.notifDir,
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
}

func (s *PluginSuite) TestBrokerRunSimple() {
	DefaultEmptyTicker = 50 * time.Millisecond

	t := s.T()
	
	pluginCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	err := pb.Init(&pluginCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       s.pluginDir,
		NotificationDir: s.notifDir,
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
