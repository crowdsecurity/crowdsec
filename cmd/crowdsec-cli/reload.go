//go:build !windows && !freebsd && !linux

package main

// generic message since we don't know the platform
const reloadMessage = "Please reload the crowdsec process for the new configuration to be effective."
