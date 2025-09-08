package hubtest

import (
	"fmt"
	"path/filepath"
)

func basename(params ...any) (any, error) {
	// keep nilaway happy
	if len(params) == 0 || params[0] == nil {
		return "", fmt.Errorf("basename: missing argument")
	}

	// keep forcetypeassert happy
	s, ok := params[0].(string)
	if !ok {
		return "", fmt.Errorf("basename: want string, got %T", params[0])
	}

	return filepath.Base(s), nil
}
