/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package diff

import (
	"reflect"
)

// Comparative ...
type Comparative struct {
	A, B *reflect.Value
}

// ComparativeList : stores indexed comparative
type ComparativeList struct {
	m    map[interface{}]*Comparative
	keys []interface{}
}

// NewComparativeList : returns a new comparative list
func NewComparativeList() *ComparativeList {
	return &ComparativeList{
		m:    make(map[interface{}]*Comparative),
		keys: make([]interface{}, 0),
	}
}

func (cl *ComparativeList) addA(k interface{}, v *reflect.Value) {
	if (*cl).m[k] == nil {
		(*cl).m[k] = &Comparative{}
		(*cl).keys = append((*cl).keys, k)
	}
	(*cl).m[k].A = v
}

func (cl *ComparativeList) addB(k interface{}, v *reflect.Value) {
	if (*cl).m[k] == nil {
		(*cl).m[k] = &Comparative{}
		(*cl).keys = append((*cl).keys, k)
	}
	(*cl).m[k].B = v
}
