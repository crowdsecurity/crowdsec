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

func TestGetPluginNameAndTypeFromPath(t *testing.T) {
	setUp()
	defer tearDown()
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name: "valid plugin name, single dash",
			args: args{
				path: path.Join(testPath, "notification-gitter"),
			},
			want:    "notification",
			want1:   "gitter",
			wantErr: false,
		},
		{
			name: "invalid plugin name",
			args: args{
				path: ".\\tests\\gitter.exe",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "valid plugin name, multiple dash",
			args: args{
				path: ".\\tests\\notification-instant-slack.exe",
			},
			want:    "notification-instant",
			want1:   "slack",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getPluginTypeAndSubtypeFromPath(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPluginNameAndTypeFromPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getPluginNameAndTypeFromPath() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getPluginNameAndTypeFromPath() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestListFilesAtPath(t *testing.T) {
	setUp()
	defer tearDown()
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
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
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := listFilesAtPath(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("listFilesAtPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("listFilesAtPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func setUp() {
	dir, err := os.MkdirTemp("./", "cs_plugin_test")
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(path.Join(dir, "slack"))
	if err != nil {
		log.Fatal(err)
	}
	f.Close()
	f, err = os.Create(path.Join(dir, "notification-gitter"))
	if err != nil {
		log.Fatal(err)
	}
	f.Close()
	err = os.Mkdir(path.Join(dir, "dummy_dir"), 0666)
	if err != nil {
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
