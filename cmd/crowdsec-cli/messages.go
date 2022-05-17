package main

import (
	"fmt"
	"runtime"
)

const (
	ReloadMessageFormat = `Run '%s' for the new configuration to be effective.`
	ReloadCmdLinux      = `sudo systemctl reload crowdsec`
	ReloadCmdFreebsd    = `sudo service crowdsec reload`
)

func ReloadMessage() string {

	var reloadCmd string

	switch runtime.GOOS {
	case "windows":
		return "Please restart the crowdsec service for the new configuration to be effective."
	case "freebsd":
		reloadCmd = ReloadCmdFreebsd
	default:
		reloadCmd = ReloadCmdLinux
	}

	return fmt.Sprintf(ReloadMessageFormat, reloadCmd)
}
