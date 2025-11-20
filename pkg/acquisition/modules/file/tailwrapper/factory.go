package tailwrapper

import (
	"fmt"
)

// TailFile creates a new Tailer based on the configuration
// It returns either a native tail adapter or a stat-based tailer
func TailFile(filename string, config Config) (Tailer, error) {
	// Determine which implementation to use
	tailMode := config.TailMode
	if tailMode == "" {
		tailMode = "native" // default to original behavior
	}

	switch tailMode {
	case "stat", "stat_poll":
		return newStatTail(filename, config)
	case "native", "nxadm", "default", "":
		return newNxadmTail(filename, config)
	default:
		return nil, fmt.Errorf("unknown tail mode: %s (supported: native/nxadm, stat)", tailMode)
	}
}
