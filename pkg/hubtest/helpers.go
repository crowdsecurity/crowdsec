package hubtest

import (
	"path/filepath"
)

func basename(params ...any) (any, error) {
	s := params[0].(string)
	return filepath.Base(s), nil
}
