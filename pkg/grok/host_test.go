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

//go test -coverprofile cover.out && go tool cover -html=cover.out -o cover.html

import (
	"bufio"
	"errors"
	"os"
	"testing"
)

const (
	patternsTest     = "patterns_pass.txt"
	patternsFailTest = "patterns_fail.txt"
)

func TestNew(t *testing.T) {
	h := New()
	if len(h.Patterns) != 0 {
		t.Error("New returns non-empty host")
	}
}

func testEmptyName(t *testing.T, h Host) {
	l := len(h.Patterns)
	if err := h.Add("", "expr"); err == nil {
		t.Error("(Host).Add is missing ErrEmptyName")
	} else if !errors.Is(err, ErrEmptyName) {
		t.Error("(Host).Add returns non-ErrEmptyName error")
	}
	if len(h.Patterns) > l {
		t.Error("added bad patterns")
	}
}

func testEmptyExpression(t *testing.T, h Host) {
	l := len(h.Patterns)
	if err := h.Add("zorro", ""); err == nil {
		t.Error("(Host).Add is missing ErrEmptyExpression")
	} else if !errors.Is(err, ErrEmptyExpression) {
		t.Error("(Host).Add returns non-ErrEmptyExpression error")
	}
	if len(h.Patterns) > l {
		t.Error("added bad patterns")
	}
}

func testNormalPattern(t *testing.T, h Host) {
	l := len(h.Patterns)
	if err := h.Add("DIGIT", `\d`); err != nil {
		t.Errorf("(Host).Add returns non-nil error: %v", err)
	}
	if len(h.Patterns) != l+1 {
		t.Error("wrong patterns count")
	}
}

// must be invoked direct after testNormalPattern
func testAlreadyExists(t *testing.T, h Host) {
	l := len(h.Patterns)
	if err := h.Add("DIGIT", `[+-](0x)?\d`); err == nil {
		t.Error("(Host).Add is missing ErrAlreadyExist")
	} else if !errors.Is(err, ErrAlreadyExist) {
		t.Error("(Host).Add returns non-ErrAlreadyExist error")
	}
	if len(h.Patterns) != l {
		t.Error("wrong patterns count")
	}
}

func TestHost_Add(t *testing.T) {
	h := New()
	testEmptyName(t, h)
	testEmptyExpression(t, h)
	testNormalPattern(t, h)
	testAlreadyExists(t, h)
	if err := h.Add("BAD", `(?![0-5])`); err == nil {
		t.Error("(Host).Add is missing any bad-regexp error")
	}
	if len(h.Patterns) != 1 {
		t.Error("wrong patterns count")
	}
	if err := h.Add("TWODIG", `%{DIGIT}-%{DIGIT}`); err != nil {
		t.Errorf("(Host).Add returns non-nil error: %v", err)
	}
	if len(h.Patterns) != 2 {
		t.Error("wrong patterns count")
	}
	if err := h.Add("THREE", `%{NOT}-%{EXIST}`); err == nil {
		t.Error("(Host).Add is missing the-pattern-not-exist error")
	}
	if len(h.Patterns) != 2 {
		t.Error("wrong patterns count")
	}
	if err := h.Add("FOUR", `%{DIGIT:one}-%{DIGIT:two}`); err != nil {
		t.Errorf("(Host).Add returns non-nil error: %v", err)
	}
	if len(h.Patterns) != 3 {
		t.Error("wrong patterns count")
	}
	if err := h.Add("FIVE", `(?!\d)%{DIGIT}(?!\d)`); err == nil {
		t.Error("(Host).Add is missing an error of regexp")
	}
	if len(h.Patterns) != 3 {
		t.Error("wrong patterns count")
	}
	if err := h.Add("SIX", `%{FOUR:four}-%{DIGIT:six}`); err != nil {
		t.Errorf("(Host).Add returns non-nil error: %v", err)
	}
	if len(h.Patterns) != 4 {
		t.Error("wrong patterns count")
	}
}

func TestHost_Compile(t *testing.T) {
	h := New()
	if _, err := h.Compile(""); err == nil {
		t.Error("(Host).Compile missing ErrEmptyExpression")
	} else if !errors.Is(err, ErrEmptyExpression) {
		t.Error("(Host).Compile returns non-ErrEmptyExpression error")
	}
	if len(h.Patterns) != 0 {
		t.Error("(Host).Compile: (bad) pattern added to host")
	}
	if p, err := h.Compile(`\d+`); err != nil {
		t.Error("(Host).Compile error:", err)
	} else if p == nil {
		t.Error("(Host).Compile returns nil (and no errors)")
	}
	if len(h.Patterns) != 0 {
		t.Error("(Host).Compile: pattern added to host")
	}
}

func TestHost_Get(t *testing.T) {
	h := New()
	if err := h.Add("DIG", `\d`); err != nil {
		t.Error(err)
	}
	if p, err := h.Get("DIG"); err != nil {
		t.Error(err)
	} else if p == nil {
		t.Error("(Host).Get returns nil (and nil-error)")
	}
	if p, err := h.Get("SEVEN"); err == nil {
		t.Error("(Host).Get is missing ErrNotExist")
	} else if p != nil {
		t.Error("(Host).Get returns non-nil not-exsted-pattern")
	}
}

func tempFile(t *testing.T) (name string) {
	f, err := os.CreateTemp(t.TempDir(), "")
	if err != nil {
		t.Skip("unable to create temporary file")
		return ""
	}
	defer f.Close()
	if _, err = f.Write(make([]byte, bufio.MaxScanTokenSize+1)); err != nil {
		t.Skip("unable to write to temporary file")
		return ""
	}
	return f.Name()
}

func TestHost_AddFromFile(t *testing.T) {
	h := New()
	if err := h.AddFromFile(patternsTest); err != nil {
		t.Error(err)
	}
	if len(h.Patterns) != 3 {
		t.Error("wrong patterns count")
	}
	if _, err := h.Get("ONE"); err != nil {
		t.Error(err)
	}
	if _, err := h.Get("TWO"); err != nil {
		t.Error(err)
	}
	if _, err := h.Get("THREE"); err != nil {
		t.Error(err)
	}
}

func TestHost_AddFromFile_malformedPatterns(t *testing.T) {
	h := New()
	if err := h.AddFromFile(patternsFailTest); err == nil {
		t.Error("(Host).AddFromFile (should fail): missing error")
	}
}

func TestHost_AddFromFile_scannerError(t *testing.T) {
	h := New()
	name := tempFile(t)
	t.Log("create tmporary file:", name)
	defer os.Remove(name)
	if err := h.AddFromFile(name); err == nil {
		t.Error("(Host).AddFromFile (should fail): missing error")
	}
}

func TestHost_inject(t *testing.T) {
	h := New()
	h.Patterns["TWO"] = `(?!\d)`
	if err := h.Add("ONE", `%{TWO:one}`); err == nil {
		t.Error("bad injection returns nil error")
	}
}

func TestHost_badPath(t *testing.T) {
	h := New()
	if err := h.AddFromFile("unexisted-file-without-patterns"); err == nil {
		t.Error("bad path with nil error")
	}
}

func TestHost_addFromLine(t *testing.T) {
	h := New()
	if err := h.addFromLine("ONE (?!\\d)"); err == nil {
		t.Error("bad line with nil error")
	}
}
