package setup

import (
	"os"
)

// here we can add more helpers as needed, for example:
// FileExists(glob)
// DirExists(glob)
// FileContains(regexp)
// ModifiedSince('1 month')
// PathExistGlob(...)

type OSPathChecker struct{}

func (OSPathChecker) Exists(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}
