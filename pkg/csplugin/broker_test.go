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

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

var testPath string

func setPluginPermTo744() {
	setPluginPermTo("744")
}

func setPluginPermTo722() {
	setPluginPermTo("722")
}

func setPluginPermTo724() {
	setPluginPermTo("724")
}
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
				path: "./tests/gitter",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "valid plugin name, multiple dash",
			args: args{
				path: "./tests/notification-instant-slack",
			},
			want:    "notification-instant",
			want1:   "slack",
			wantErr: false,
		},
	}
	for _, tt := range tests {
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
			action:  setPluginPermTo744,
			wantErr: false,
		},
		{
			name:        "group writable binary",
			wantErr:     true,
			errContains: "notification-dummy is world writable",
			action:      setPluginPermTo722,
		},
		{
			name:        "group writable binary",
			wantErr:     true,
			errContains: "notification-dummy is group writable",
			action:      setPluginPermTo724,
		},
		{
			name:        "no plugin dir",
			wantErr:     true,
			errContains: "no such file or directory",
			action:      tearDown,
		},
		{
			name:        "no plugin binary",
			wantErr:     true,
			errContains: "binary for plugin dummy_default not found",
			action: func() {
				err := os.Remove(path.Join(testPath, "notification-dummy"))
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:        "only specify user",
			wantErr:     true,
			errContains: "both plugin user and group must be set",
			procCfg: csconfig.PluginCfg{
				User: "123445555551122toto",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "only specify group",
			wantErr:     true,
			errContains: "both plugin user and group must be set",
			procCfg: csconfig.PluginCfg{
				Group: "123445555551122toto",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "Fails to run as root",
			wantErr:     true,
			errContains: "operation not permitted",
			procCfg: csconfig.PluginCfg{
				User:  "root",
				Group: "root",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "Invalid user and group",
			wantErr:     true,
			errContains: "unknown user toto1234",
			procCfg: csconfig.PluginCfg{
				User:  "toto1234",
				Group: "toto1234",
			},
			action: setPluginPermTo744,
		},
		{
			name:        "Valid user and invalid group",
			wantErr:     true,
			errContains: "unknown group toto1234",
			procCfg: csconfig.PluginCfg{
				User:  "nobody",
				Group: "toto1234",
			},
			action: setPluginPermTo744,
		},
	}

	for _, test := range tests {
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
	setPluginPermTo744()
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

	assert.FileExists(t, "./out")
	assert.Equal(t, types.GetLineCountForFile("./out"), 2)
}

func buildDummyPlugin() {
	dir, err := os.MkdirTemp("./tests", "cs_plugin_test")
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", path.Join(dir, "notification-dummy"), "../../plugins/notifications/dummy/")
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
	testPath = dir
}

func setPluginPermTo(perm string) {
	if err := exec.Command("chmod", perm, path.Join(testPath, "notification-dummy")).Run(); err != nil {
		log.Fatal(errors.Wrapf(err, "chmod 744 %s", path.Join(testPath, "notification-dummy")))
	}
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
