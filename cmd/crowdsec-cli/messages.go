package main

import (
	"fmt"
	"runtime"
)

// ReloadMessage returns a description of the task required to reload
// the crowdsec configuration, according to the operating system.
func ReloadMessage() string {
	var msg string

	switch runtime.GOOS {
	case "windows":
		msg = "Please restart the crowdsec service"
	case "freebsd":
		msg = `Run 'sudo service crowdsec reload'`
	default:
		msg = `Run 'sudo systemctl reload crowdsec'`
	}

	return fmt.Sprintf("%s for the new configuration to be effective.", msg)
}
