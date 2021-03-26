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

	if runtime.GOOS == "freebsd" {
		reloadCmd = ReloadCmdFreebsd
	} else {
		reloadCmd = ReloadCmdLinux
	}

	return fmt.Sprintf(ReloadMessageFormat, reloadCmd)
}
