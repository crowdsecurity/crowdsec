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
		tailMode = "default"
	}

	switch tailMode {
	case "stat":
		return newStatTail(filename, config)
	case "default":
		return newNxadmTail(filename, config)
	default:
		return nil, fmt.Errorf("unknown tail mode: %s (supported: default, stat)", tailMode)
	}
}
