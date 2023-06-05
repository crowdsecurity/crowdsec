//go:build linux || freebsd || netbsd || openbsd || solaris || !windows

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
			path:  "/path/to/notification-gitter",
			want:  "notification",
			want1: "gitter",
		},
		{
			name:        "invalid plugin name",
			path:        "/path/to/gitter",
			expectedErr: "plugin name /path/to/gitter is invalid. Name should be like {type-name}",
		},
		{
			name:  "valid plugin name, multiple dash",
			path:  "/path/to/notification-instant-slack",
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
