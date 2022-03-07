/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package diff

import (
	"reflect"
	"time"
)

func (d *Differ) diffTime(path []string, a, b reflect.Value) error {
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

	// Marshal and unmarshal time type will lose accuracy. Using unix nano to compare time type.
	au := a.Interface().(time.Time).UnixNano()
	bu := b.Interface().(time.Time).UnixNano()

	if au != bu {
		d.cl.Add(UPDATE, path, a.Interface(), b.Interface())
	}

	return nil
}
