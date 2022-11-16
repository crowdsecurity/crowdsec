// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqltool

import (
	"path/filepath"
	"syscall"
)

func hidden(path string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	p, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return false, err
	}
	attr, err := syscall.GetFileAttributes(p)
	if err != nil {
		return false, err
	}
	return attr&syscall.FILE_ATTRIBUTE_HIDDEN != 0, nil
}
