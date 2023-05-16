/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package diff

import (
	"reflect"
)

func (d *Differ) diffInt(path []string, a, b reflect.Value, parent interface{}) error {
	if a.Kind() == reflect.Invalid {
		d.cl.Add(CREATE, path, nil, b.Interface())
		return nil
	}

	if b.Kind() == reflect.Invalid {
		d.cl.Add(DELETE, path, a.Interface(), nil)
		return nil
	}

	if a.Kind() != b.Kind() {
		return ErrTypeMismatch
	}

	if a.Int() != b.Int() {
		if a.CanInterface() {
			d.cl.Add(UPDATE, path, a.Interface(), b.Interface(), parent)
		} else {
			d.cl.Add(UPDATE, path, a.Int(), b.Int(), parent)
		}
	}

	return nil
}
