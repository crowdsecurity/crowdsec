//
// Copyright (c) 2016-2017 Konstanin Ivanov <kostyarin.ivanov@gmail.com>.
// All rights reserved. This program is free software. It comes without
// any warranty, to the extent permitted by applicable law. You can
// redistribute it and/or modify it under the terms of the Do What
// The Fuck You Want To Public License, Version 2, as published by
// Sam Hocevar. See LICENSE file for more details or see below.
//

//
//        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
//

package grok

import (
	"testing"
)

func terr(t *testing.T, err error) {
	if err != nil {
		t.Error(err)
	}
}

// parseMap collects the captures into a fresh map. These tests compare whole maps, which is
// the shape Parse used to return before ParseInto replaced it.
func parseMap(p Pattern, input string) map[string]string {
	m := make(map[string]string)
	p.ParseInto(input, m)
	return m
}

func mssTest(expect, got map[string]string) bool {
	if len(expect) != len(got) {
		return false
	}
	for k, v := range expect {
		if v != got[k] {
			return false
		}
	}
	return true
}

func TestPattern_Parse(t *testing.T) {
	h := New()
	// compile
	terr(t, h.Add("ONE", `\d`))
	terr(t, h.Add("TWO", `%{ONE:one}-%{ONE:two}`))
	terr(t, h.Add("THREE", `%{ONE:zero}-%{TWO:three}`))
	//
	if p, err := h.Get("ONE"); err != nil {
		t.Error(err)
	} else if !mssTest(nil, parseMap(p, "1")) {
		t.Error("unnamed result")
	}
	p, err := h.Get("TWO")
	if err != nil {
		t.Error(err)
	}
	if !mssTest(map[string]string{"one": "1", "two": "2"}, parseMap(p, "1-2")) {
		t.Error("bad result")
	}
	p, err = h.Get("THREE")
	if err != nil {
		t.Error(err)
	}
	if !mssTest(map[string]string{
		"one":   "1",
		"two":   "2",
		"zero":  "0",
		"three": "1-2",
	}, parseMap(p, "0-1-2")) {
		t.Error("bad result")
	}
	if err := h.Add("FOUR", `%{TWO:two}`); err != nil {
		t.Error(err)
	}
	p, err = h.Get("FOUR")
	if err != nil {
		t.Error(err)
	}
	if !mssTest(map[string]string{"one": "1", "two": "1-2"}, parseMap(p, "1-2")) {
		t.Error("bad result")
	}
}

func TestPattern_nestedGroups(t *testing.T) {
	h := New()
	if err := h.Add("ONE", `\d`); err != nil {
		t.Error(err)
	}
	if err := h.Add("TWO", `(?:%{ONE:one})-(?:%{ONE:two})?`); err != nil {
		t.Error(err)
	}
	p, err := h.Get("TWO")
	if err != nil {
		t.Error(err)
	}
	mss := parseMap(p, "1-2")
	if len(mss) != 2 ||
		mss["one"] != "1" ||
		mss["two"] != "2" {
		t.Error("bad result")
	}
	mss = parseMap(p, "1-")
	if len(mss) != 2 ||
		mss["one"] != "1" ||
		mss["two"] != "" {
		t.Error("bad result")
	}
}

func TestPattern_Names(t *testing.T) {
	h := New()
	if err := h.Add("ONE", `\d`); err != nil {
		t.Error(err)
	}
	if err := h.Add("TWO", `%{ONE:one}-%{ONE:two}`); err != nil {
		t.Error(err)
	}
	if err := h.Add("THREE", `%{ONE:zero}-%{TWO:three}`); err != nil {
		t.Error(err)
	}
	p, err := h.Get("THREE")
	if err != nil {
		t.Fatal(err)
	}
	ss := p.Names()
	if len(ss) != 4 {
		t.Error("Names returns wrong values count")
	}
	for _, v := range ss {
		if v != "one" && v != "two" && v != "zero" && v != "three" {
			t.Error("Names returns wrong values:", v)
		}
	}
}
