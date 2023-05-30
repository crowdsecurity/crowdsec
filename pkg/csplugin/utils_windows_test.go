//go:build windows

package csplugin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"
)

func TestGetPluginNameAndTypeFromPath(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name        string
		args        args
		want        string
		want1       string
		expectedErr string
	}{
		{
			name: "valid plugin name, single dash",
			args: args{
				path: "c:\\path\\to\\notification-gitter",
			},
			want:    "notification",
			want1:   "gitter",
		},
		{
			name: "invalid plugin name",
			args: args{
				path: "c:\\path\\to\\gitter.exe",
			},
			expectedErr: "something"
		},
		{
			name: "valid plugin name, multiple dash",
			args: args{
				path: "c:\\path\\to\\notification-instant-slack.exe",
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
