//go:build linux || freebsd || netbsd || openbsd || solaris || !windows

package csplugin

import (
	"encoding/json"
	"os"
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
			_, err := s.InitBroker(&tc.procCfg)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func (s *PluginSuite) TestBrokerNoThreshold() {
	var alerts []models.Alert
	DefaultEmptyTicker = 50 * time.Millisecond

	t := s.T()

	pb, err := s.InitBroker(nil)
	assert.NoError(t, err)

	tomb := tomb.Tomb{}
	go pb.Run(&tomb)

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

	// set groupwait and groupthreshold, should honor whichever comes first
	cfg := s.readconfig()
	cfg.GroupThreshold = 4
	cfg.GroupWait = 1 * time.Second
	s.writeconfig(cfg)

	pb, err := s.InitBroker(nil)
	assert.NoError(t, err)

	tomb := tomb.Tomb{}
	go pb.Run(&tomb)

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

	// set groupwait and groupthreshold, should honor whichever comes first
	cfg := s.readconfig()
	cfg.GroupThreshold = 4
	cfg.GroupWait = 4 * time.Second
	s.writeconfig(cfg)

	pb, err := s.InitBroker(nil)
	assert.NoError(t, err)

	tomb := tomb.Tomb{}
	go pb.Run(&tomb)

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

	// set groupwait
	cfg := s.readconfig()
	cfg.GroupThreshold = 4
	s.writeconfig(cfg)

	pb, err := s.InitBroker(nil)
	assert.NoError(t, err)

	tomb := tomb.Tomb{}
	go pb.Run(&tomb)

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

	// set groupwait
	cfg := s.readconfig()
	cfg.GroupWait = 1 * time.Second
	s.writeconfig(cfg)

	pb, err := s.InitBroker(nil)
	assert.NoError(t, err)

	tomb := tomb.Tomb{}
	go pb.Run(&tomb)

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
	
	pb, err := s.InitBroker(nil)
	assert.NoError(t, err)

	tomb := tomb.Tomb{}
	go pb.Run(&tomb)

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
