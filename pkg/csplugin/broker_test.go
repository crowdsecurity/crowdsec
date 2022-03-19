package csplugin

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"reflect"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

var testPath string

func Test_getPluginNameAndTypeFromPath(t *testing.T) {
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

func Test_listFilesAtPath(t *testing.T) {
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
				path.Join(testPath, "notification-gitter"),
				path.Join(testPath, "slack"),
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
	}{
		{
			name:    "valid config",
			action:  makePluginValid,
			wantErr: false,
		},
		{
			name:        "group writable binary",
			wantErr:     true,
			errContains: "notification-dummy is group writable",
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
				os.Remove(path.Join(testPath, "notification-dummy"))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer tearDown()
			buildDummyPlugin()
			if test.action != nil {
				test.action()
			}
			procCfg := csconfig.PluginCfg{}
			pb := PluginBroker{}
			profiles := csconfig.NewDefaultConfig().API.Server.Profiles
			profiles = append(profiles, &csconfig.ProfileCfg{
				Notifications: []string{"dummy_default"},
			})
			err := pb.Init(&procCfg, profiles, &csconfig.ConfigurationPaths{
				PluginDir:       testPath,
				NotificationDir: path.Join(testPath, "notifications"),
			})
			if test.wantErr {
				assert.ErrorContains(t, err, test.errContains)
			} else {
				assert.NoError(t, err)
			}

		})
	}
}

// func TestBroker(t *testing.T) {
// 	buildDummyPlugin()
// 	makePluginValid()
// 	defer tearDown()
// 	procCfg := csconfig.PluginCfg{}
// 	pb := PluginBroker{}
// 	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
// 	profiles = append(profiles, &csconfig.ProfileCfg{
// 		Notifications: []string{"dummy_default"},
// 	})
// 	err := pb.Init(&procCfg, profiles, &csconfig.ConfigurationPaths{
// 		PluginDir:       testPath,
// 		NotificationDir: "./tests",
// 	})
// 	assert.NoError(t, err)
// 	// go pb.Run(&testTomb)
// 	// defer resetTestTomb()

// }

func buildDummyPlugin() {
	dir, err := ioutil.TempDir("./tests", "cs_plugin_test")
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", path.Join(dir, "notification-dummy"), "../../plugins/notifications/dummy/")
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
	os.Mkdir(path.Join(dir, "notifications"), 0755)
	cmd = exec.Command("cp", "../../plugins/notifications/dummy/dummy.yaml", path.Join(dir, "notifications/dummy.yaml"))
	if err := cmd.Run(); err != nil {
		log.Fatal(errors.Wrapf(err, "cp ../../plugins/notifications/dummy/dummy.yaml %s", path.Join(dir, "notifications/dummy.yaml")))
	}
	testPath = dir
}

func makePluginValid() {
	if err := exec.Command("chmod", "744", path.Join(testPath, "notification-dummy")).Run(); err != nil {
		log.Fatal(errors.Wrapf(err, "chmod 744 %s", path.Join(testPath, "notification-dummy")))
	}
}

func setUp() {
	dir, err := ioutil.TempDir("./", "cs_plugin_test")
	if err != nil {
		log.Fatal(err)
	}
	_, err = os.Create(path.Join(dir, "slack"))
	if err != nil {
		log.Fatal(err)
	}
	_, err = os.Create(path.Join(dir, "notification-gitter"))
	if err != nil {
		log.Fatal(err)
	}
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
