//go:build windows

package csplugin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"
)

func TestGetPluginNameAndTypeFromPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		want        string
		want1       string
		expectedErr string
	}{
		{
			name:  "valid plugin name, single dash",
			path:  "c:\\path\\to\\notification-gitter",
			want:  "notification",
			want1: "gitter",
		},
		{
			name:        "invalid plugin name",
			path:        "c:\\path\\to\\gitter.exe",
			expectedErr: "plugin name c:\\path\\to\\gitter.exe is invalid. Name should be like {type-name}",
		},
		{
			name:  "valid plugin name, multiple dash",
			path:  "c:\\path\\to\\notification-instant-slack.exe",
			want:  "notification-instant",
			want1: "slack",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, got1, err := getPluginTypeAndSubtypeFromPath(tc.path)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want1, got1)
		})
	}
}
