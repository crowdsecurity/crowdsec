// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

//go:build !windows

package sqltool

import "path/filepath"

func hidden(path string) (bool, error) {
	return filepath.Base(path)[0] == '.', nil
}
