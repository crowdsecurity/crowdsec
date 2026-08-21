//go:build linux || freebsd || netbsd || openbsd || solaris || (!windows && !js)

package csplugin

import (
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
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
		t.Run(tc.name, func(t *testing.T) {
			got, got1, err := getPluginTypeAndSubtypeFromPath(tc.path)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want1, got1)
		})
	}
}

func writePlugin(t *testing.T, dir string, name string, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), mode))
	require.NoError(t, os.Chmod(path, mode))

	return path
}

func rootOwnedPlugin(t *testing.T, dir string) (string, bool) {
	t.Helper()

	if os.Geteuid() == rootUID {
		return writePlugin(t, dir, "notification-root", 0o755), true
	}

	for _, candidate := range []string{"/bin/true", "/usr/bin/env"} {
		details, err := os.Stat(candidate)
		if err != nil {
			continue
		}

		if details.Sys().(*syscall.Stat_t).Uid == rootUID && details.Mode().Perm()&0o022 == 0 {
			return candidate, true
		}
	}

	return "", false
}

func skipUnless(cond bool, reason string) string {
	if cond {
		return ""
	}

	return reason
}

func TestPluginIsValidForUser(t *testing.T) {
	dir := t.TempDir()

	currentUser, err := user.Current()
	require.NoError(t, err)

	otherUser := &user.User{Uid: "12345", Username: "not-the-current-user"}

	rootPath, hasRootPath := rootOwnedPlugin(t, dir)

	tests := []struct {
		name        string
		path        string
		user        *user.User
		expectedErr string
		skip        string
	}{
		{
			name: "owned by the current user",
			path: writePlugin(t, dir, "notification-mine", 0o755),
			user: currentUser,
		},
		{
			name: "owned by root, running as another user",
			path: rootPath,
			user: otherUser,
			skip: skipUnless(hasRootPath, "no root-owned executable available"),
		},
		{
			name:        "owned by neither the current user nor root",
			path:        writePlugin(t, dir, "notification-foreign", 0o755),
			user:        otherUser,
			expectedErr: "is not owned by root or by the current user 'not-the-current-user'",
			skip:        skipUnless(os.Geteuid() != rootUID, "running as root, new files are root-owned"),
		},
		{
			name:        "world writable",
			path:        writePlugin(t, dir, "notification-world", 0o757),
			user:        currentUser,
			expectedErr: "is world writable, world writable plugins are invalid",
		},
		{
			name:        "group writable",
			path:        writePlugin(t, dir, "notification-group", 0o775),
			user:        currentUser,
			expectedErr: "is group writable, group writable plugins are invalid",
		},
		{
			name:        "does not exist",
			path:        filepath.Join(dir, "notification-missing"),
			user:        currentUser,
			expectedErr: "does not exist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}

			cstest.RequireErrorContains(t, pluginIsValidForUser(tc.path, tc.user), tc.expectedErr)
		})
	}
}
