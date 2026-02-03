package tailwrapper

import (
	"context"
)

// TailFile creates a new Tailer with the specified configuration.
//
// The behavior depends on config.KeepFileOpen:
//   - true:  keeps file handle open, uses fsnotify for change detection (better for local files)
//   - false: opens/reads/closes on each poll cycle (better for network shares like Azure SMB)
func TailFile(ctx context.Context, filename string, config Config) (Tailer, error) {
	return newTailer(ctx, filename, config)
}
