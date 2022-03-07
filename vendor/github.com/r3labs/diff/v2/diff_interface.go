/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package diff

import "reflect"

func (d *Differ) diffInterface(path []string, a, b reflect.Value, parent interface{}) error {
	if a.Kind() == reflect.Invalid {
		d.cl.Add(CREATE, path, nil, exportInterface(b))
		return nil
	}

	if b.Kind() == reflect.Invalid {
		d.cl.Add(DELETE, path, exportInterface(a), nil)
		return nil
	}

	if a.Kind() != b.Kind() {
		return ErrTypeMismatch
	}

	if a.IsNil() && b.IsNil() {
		return nil
	}

	if a.IsNil() {
		d.cl.Add(UPDATE, path, nil, exportInterface(b), parent)
		return nil
	}

	if b.IsNil() {
		d.cl.Add(UPDATE, path, exportInterface(a), nil, parent)
		return nil
	}

	return d.diff(path, a.Elem(), b.Elem(), parent)
}
