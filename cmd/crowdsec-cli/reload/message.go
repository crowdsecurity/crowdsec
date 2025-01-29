//go:build !windows && !freebsd && !linux

package reload

// generic message since we don't know the platform
const message = "Please reload the crowdsec process for the new configuration to be effective."
