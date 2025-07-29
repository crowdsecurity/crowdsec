package setup

import (
	"context"
	"os"
	"path/filepath"
)

type OSExprPath struct{}

func (OSExprPath) Exists(_ context.Context, path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (OSExprPath) Glob(_ context.Context, pattern string) []string {
	ret, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}

	return ret
}
