//go:build windows

package csplugin

import (
	"log"
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

var testPath string

func TestBrokerInit(t *testing.T) {
	tests := []struct {
		name        string
		action      func()
		errContains string
		wantErr     bool
		procCfg     csconfig.PluginCfg
	}{
		{
			name:    "valid config",
			wantErr: false,
		},
		{
			name:        "no plugin dir",
			wantErr:     true,
			errContains: cstest.FileNotFoundMessage,
			action:      tearDown,
		},
		{
			name:        "no plugin binary",
			wantErr:     true,
			errContains: "binary for plugin dummy_default not found",
			action: func() {
				err := os.Remove(path.Join(testPath, "notification-dummy.exe"))
				if err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			defer tearDown()
			buildDummyPlugin()
			if test.action != nil {
				test.action()
			}
			pb := PluginBroker{}
			profiles := csconfig.NewDefaultConfig().API.Server.Profiles
			profiles = append(profiles, &csconfig.ProfileCfg{
				Notifications: []string{"dummy_default"},
			})
			err := pb.Init(&test.procCfg, profiles, &csconfig.ConfigurationPaths{
				PluginDir:       testPath,
				NotificationDir: "./tests/notifications",
			})
			defer pb.Kill()
			if test.wantErr {
				assert.ErrorContains(t, err, test.errContains)
			} else {
				assert.NoError(t, err)
			}

		})
	}
}

func TestBrokerRun(t *testing.T) {
	buildDummyPlugin()
	defer tearDown()
	procCfg := csconfig.PluginCfg{}
	pb := PluginBroker{}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	err := pb.Init(&procCfg, profiles, &csconfig.ConfigurationPaths{
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
	time.Sleep(time.Second * 4)

	assert.FileExists(t, ".\\out")
	assert.Equal(t, types.GetLineCountForFile(".\\out"), 2)
}

func buildDummyPlugin() {
	dir, err := os.MkdirTemp(".\\tests", "cs_plugin_test")
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", path.Join(dir, "notification-dummy.exe"), "../../plugins/notifications/dummy/")
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
	testPath = dir
}

func tearDown() {
	err := os.RemoveAll(testPath)
	if err != nil {
		log.Fatal(err)
	}
}
