/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package diff

import "regexp"

func pathmatch(filter, path []string) bool {
	for i, f := range filter {
		if len(path) < i+1 {
			return false
		}

		matched, _ := regexp.MatchString(f, path[i])
		if !matched {
			return false
		}
	}

	return true
}
