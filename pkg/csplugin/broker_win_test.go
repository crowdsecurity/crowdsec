//go:build windows

package csplugin

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

/*
Due to the complexity of file permission modification with go on windows, we only test the basic behavior the broker,
not if it will actually reject plugins with invalid permissions
*/

func (s *PluginSuite) TestBrokerInit() {
	tests := []struct {
		name        string
		action      func(*testing.T)
		procCfg     csconfig.PluginCfg
		expectedErr string
	}{
		{
			name:    "valid config",
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
	}

	for _, tc := range tests {
		tc := tc
		s.Run(tc.name, func() {
			t := s.T()
			if test.action != nil {
				test.action(t)
			}
			pb := PluginBroker{}
			profiles := csconfig.NewDefaultConfig().API.Server.Profiles
			profiles = append(profiles, &csconfig.ProfileCfg{
				Notifications: []string{"dummy_default"},
			})
			err := pb.Init(&test.procCfg, profiles, &csconfig.ConfigurationPaths{
				PluginDir:       s.pluginDir,
				NotificationDir: s.notifDir,
			})
			defer pb.Kill()
			cstest.RequireErrorContains(t, err, test.expectedErr)
		})
	}
}

func (s *PluginSuite) TestBrokerRun() {
	t := s.T()
	procCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	err := pb.Init(&procCfg, profiles, &csconfig.ConfigurationPaths{
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
	time.Sleep(time.Second * 4)

	assert.FileExists(t, ".\\out")
	assert.Equal(t, types.GetLineCountForFile(".\\out"), 2)
}
