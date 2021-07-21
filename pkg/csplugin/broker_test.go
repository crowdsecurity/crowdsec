package csplugin

import (
	"reflect"
	"testing"

	plugin "github.com/hashicorp/go-plugin"
)

func Test_getPluginNameAndTypeFromPath(t *testing.T) {
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
				path: "./tests/notification-gitter",
			},
			want:    "gitter",
			want1:   "notification",
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
			want:    "slack",
			want1:   "notification-instant",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getPluginNameAndTypeFromPath(tt.args.path)
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
				path: "./tests",
			},
			want: []string{
				"tests/notification-gitter",
				"tests/slack",
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

func TestPluginBroker_BuildPluginMap(t *testing.T) {
	pb := PluginBroker{pluginMap: make(map[string]plugin.Plugin)}
	err := pb.loadPlugins("./tests")

	if err != nil {
		t.Error(err)
	}

	expectedPluginMap := map[string]plugin.Plugin{
		"gitter": &NotifierPlugin{},
	}

	if !reflect.DeepEqual(expectedPluginMap, pb.pluginMap) {
		t.Errorf("expected= %v, found= %v", expectedPluginMap, pb.pluginMap)
	}
}
