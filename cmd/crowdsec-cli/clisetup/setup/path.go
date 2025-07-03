package setup

import (
	"os"
)

type OSPathChecker struct{}

func (OSPathChecker) Exists(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}
