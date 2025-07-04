package setup

import (
	"os"
)

// here we can add more helpers like DirExists, FileContains, etc.

type OSPathChecker struct{}

func (OSPathChecker) Exists(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}
