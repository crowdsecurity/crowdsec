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

// Package grokky is a pure Golang Grok-like patterns library. This can
// help you to parse log files and other. This is based on RE2 regexp
// that much more faster then Oniguruma. The library disigned for creating
// many patterns and using it many times. The behavior and capabilities
// are slightly different from the original library. The golas of the
// library are: (1) simplicity, (2) performance, (3) ease of use.
package grokky

// http://play.golang.org/p/vb18r_OZkK

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/wasilibs/go-re2"
)

var patternRegexp = regexp.MustCompile(`\%\{(\w+)(\:(\w+))?}`)

var (
	// ErrEmptyName arises when pattern name is an empty string
	ErrEmptyName = errors.New("an empty name")
	// ErrEmptyExpression arises when expression is an empty string
	ErrEmptyExpression = errors.New("an empty expression")
	// ErrAlreadyExist arises when pattern with given name alrady exists
	ErrAlreadyExist = errors.New("the pattern already exist")
	// ErrNotExist arises when pattern with given name doesn't exists
	ErrNotExist = errors.New("pattern doesn't exist")
)

// Host is a patterns collection. Feel free to
// delete the Host after all patterns (that you need)
// are created. Think of it as a kind of factory.
type Host struct {
	Patterns map[string]string
	UseRe2   bool
}

// New returns new empty host
func New() Host {
	return Host{
		Patterns: make(map[string]string),
	}
}

// Add a new pattern to the Host. If pattern with given name
// already exists the ErrAlreadyExists will be retuned.
func (h Host) Add(name, expr string) error {
	if name == "" {
		return ErrEmptyName
	}
	if expr == "" {
		return ErrEmptyExpression
	}
	if _, ok := h.Patterns[name]; ok {
		return ErrAlreadyExist
	}
	if h.UseRe2 {
		if _, err := h.compileExternalRe2(expr); err != nil {
			return err
		}
	} else {
		if _, err := h.compileExternal(expr); err != nil {
			return err
		}
	}
	h.Patterns[name] = expr
	return nil
}

func (h Host) compile(name string) (Pattern, error) {
	expr, ok := h.Patterns[name]
	if !ok {
		return nil, ErrNotExist
	}
	if h.UseRe2 {
		return h.compileExternalRe2(expr)
	} else {
		return h.compileExternal(expr)
	}
}

func (h Host) compileExternal(expr string) (*PatternLegacy, error) {

	// find subpatterns
	subs := patternRegexp.FindAllString(expr, -1)
	// this semantics set
	ts := make(map[string]struct{})
	// chek: does subpatterns exist into this Host?
	for _, s := range subs {
		name, sem := split(s)
		if _, ok := h.Patterns[name]; !ok {
			return nil, fmt.Errorf("the '%s' pattern doesn't exist", name)
		}
		ts[sem] = struct{}{}
	}
	// if there are not subpatterns
	if len(subs) == 0 {
		r, err := regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
		return &PatternLegacy{Regexp: r}, nil
	}
	// split
	spl := patternRegexp.Split(expr, -1)
	// concat it back
	msi := make(map[string]int)
	order := 1 // semantic order
	var res string
	for i := 0; i < len(spl)-1; i++ {
		// split part
		splPart := spl[i]
		order += capCount(splPart)
		// subs part
		sub := subs[i]
		subName, subSem := split(sub)
		p, err := h.compile(subName)
		if err != nil {
			return nil, err
		}
		pattern := p.(*PatternLegacy)
		sub = pattern.String()
		subNumSubexp := pattern.NumSubexp()
		subNumSubexp++
		sub = wrap(sub)
		if subSem != "" {
			msi[subSem] = order
		}
		res += splPart + sub
		// add sub semantics to this semantics
		for k, v := range pattern.s {
			if _, ok := ts[k]; !ok {
				msi[k] = order + v
			}
		}
		// increse the order
		order += subNumSubexp
	} // last spl
	res += spl[len(spl)-1]
	r, err := regexp.Compile(res)
	if err != nil {
		return nil, err
	}
	p := &PatternLegacy{Regexp: r}
	p.s = msi
	return p, nil
}

func (h Host) compileExternalRe2(expr string) (*PatternRe2, error) {

	// find subpatterns
	subs := patternRegexp.FindAllString(expr, -1)
	// this semantics set
	ts := make(map[string]struct{})
	// chek: does subpatterns exist into this Host?
	for _, s := range subs {
		name, sem := split(s)
		if _, ok := h.Patterns[name]; !ok {
			return nil, fmt.Errorf("the '%s' pattern doesn't exist", name)
		}
		ts[sem] = struct{}{}
	}
	// if there are not subpatterns
	if len(subs) == 0 {
		r, err := re2.Compile(expr)
		if err != nil {
			return nil, err
		}
		return &PatternRe2{Regexp: r}, nil
	}
	// split
	spl := patternRegexp.Split(expr, -1)
	// concat it back
	msi := make(map[string]int)
	order := 1 // semantic order
	var res string
	for i := 0; i < len(spl)-1; i++ {
		// split part
		splPart := spl[i]
		order += capCount(splPart)
		// subs part
		sub := subs[i]
		subName, subSem := split(sub)
		p, err := h.compile(subName)
		if err != nil {
			return nil, err
		}
		pattern := p.(*PatternRe2)
		sub = pattern.String()
		subNumSubexp := pattern.NumSubexp()
		subNumSubexp++
		sub = wrap(sub)
		if subSem != "" {
			msi[subSem] = order
		}
		res += splPart + sub
		// add sub semantics to this semantics
		for k, v := range pattern.s {
			if _, ok := ts[k]; !ok {
				msi[k] = order + v
			}
		}
		// increse the order
		order += subNumSubexp
	} // last spl
	res += spl[len(spl)-1]
	r, err := re2.Compile(res)
	if err != nil {
		return nil, err
	}
	p := &PatternRe2{Regexp: r}
	p.s = msi
	return p, nil
}

// Get pattern by name from the Host
func (h Host) Get(name string) (Pattern, error) {
	return h.compile(name)
}

// Compile and get pattern without name (and without adding it to this Host)
func (h Host) Compile(expr string) (Pattern, error) {
	if expr == "" {
		return nil, ErrEmptyExpression
	}
	if h.UseRe2 {
		return h.compileExternalRe2(expr)
	} else {
		return h.compileExternal(expr)
	}
}

var lineRegexp = regexp.MustCompile(`^(\w+)\s+(.+)$`)

func (h Host) addFromLine(line string) error {
	sub := lineRegexp.FindStringSubmatch(line)
	if len(sub) == 0 { // not match
		return nil
	}
	return h.Add(sub[1], sub[2])
}

// AddFromFile appends all patterns from the file to this Host.
func (h Host) AddFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := h.addFromLine(scanner.Text()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
