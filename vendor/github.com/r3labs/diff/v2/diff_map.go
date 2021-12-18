/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package diff

import (
	"fmt"
	"reflect"

	"github.com/vmihailenco/msgpack"
)

func (d *Differ) diffMap(path []string, a, b reflect.Value) error {
	if a.Kind() == reflect.Invalid {
		return d.mapValues(CREATE, path, b)
	}

	if b.Kind() == reflect.Invalid {
		return d.mapValues(DELETE, path, a)
	}

	c := NewComparativeList()

	for _, k := range a.MapKeys() {
		ae := a.MapIndex(k)
		c.addA(exportInterface(k), &ae)
	}

	for _, k := range b.MapKeys() {
		be := b.MapIndex(k)
		c.addB(exportInterface(k), &be)
	}

	return d.diffComparative(path, c, exportInterface(a))
}

func (d *Differ) mapValues(t string, path []string, a reflect.Value) error {
	if t != CREATE && t != DELETE {
		return ErrInvalidChangeType
	}

	if a.Kind() == reflect.Ptr {
		a = reflect.Indirect(a)
	}

	if a.Kind() != reflect.Map {
		return ErrTypeMismatch
	}

	x := reflect.New(a.Type()).Elem()

	for _, k := range a.MapKeys() {
		ae := a.MapIndex(k)
		xe := x.MapIndex(k)

		var err error
		if d.StructMapKeys {
			//it's not enough to turn k to a string, we need to able to  marshal a type when
			//we apply it in patch so... we'll marshal it to JSON
			var b []byte
			if b, err = msgpack.Marshal(k.Interface()); err == nil {
				err = d.diff(append(path, string(b)), xe, ae, a.Interface())
			}
		} else {
			err = d.diff(append(path, fmt.Sprint(k.Interface())), xe, ae, a.Interface())
		}
		if err != nil {
			return err
		}
	}

	for i := 0; i < len(d.cl); i++ {
		// only swap changes on the relevant map
		if pathmatch(path, d.cl[i].Path) {
			d.cl[i] = swapChange(t, d.cl[i])
		}
	}

	return nil
}
