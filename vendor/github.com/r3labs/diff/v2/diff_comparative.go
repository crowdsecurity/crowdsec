/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package diff

import (
	"reflect"
)

func (d *Differ) diffComparative(path []string, c *ComparativeList, parent interface{}) error {
	for _, k := range c.keys {
		id := idstring(k)
		if d.StructMapKeys {
			id = idComplex(k)
		}

		fpath := copyAppend(path, id)
		nv := reflect.ValueOf(nil)

		if c.m[k].A == nil {
			c.m[k].A = &nv
		}

		if c.m[k].B == nil {
			c.m[k].B = &nv
		}

		err := d.diff(fpath, *c.m[k].A, *c.m[k].B, parent)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Differ) comparative(a, b reflect.Value) bool {
	if a.Len() > 0 {
		ae := a.Index(0)
		ak := getFinalValue(ae)

		if ak.Kind() == reflect.Struct {
			if identifier(d.TagName, ak) != nil {
				return true
			}
		}
	}

	if b.Len() > 0 {
		be := b.Index(0)
		bk := getFinalValue(be)

		if bk.Kind() == reflect.Struct {
			if identifier(d.TagName, bk) != nil {
				return true
			}
		}
	}

	return false
}
