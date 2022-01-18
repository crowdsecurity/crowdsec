package csplugin

import (
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"
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

func setUp() {
	testMode = true
	dir, err := ioutil.TempDir("./", "cs_plugin_test")
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
