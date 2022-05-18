//
// from https://github.com/uber-go/config/tree/master/internal/merge
//
// Copyright (c) 2019 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package yamlpatch

import (
	"bytes"
	"fmt"
	"io"

	"github.com/pkg/errors"

	yaml "gopkg.in/yaml.v2"
)

type (
	// YAML has three fundamental types. When unmarshaled into interface{},
	// they're represented like this.
	mapping  = map[interface{}]interface{}
	sequence = []interface{}
)

// YAML deep-merges any number of YAML sources, with later sources taking
// priority over earlier ones.
//
// Maps are deep-merged. For example,
//   {"one": 1, "two": 2} + {"one": 42, "three": 3}
//   == {"one": 42, "two": 2, "three": 3}
// Sequences are replaced. For example,
//   {"foo": [1, 2, 3]} + {"foo": [4, 5, 6]}
//   == {"foo": [4, 5, 6]}
//
// In non-strict mode, duplicate map keys are allowed within a single source,
// with later values overwriting previous ones. Attempting to merge
// mismatched types (e.g., merging a sequence into a map) replaces the old
// value with the new.
//
// Enabling strict mode returns errors in both of the above cases.
func YAML(sources [][]byte, strict bool) (*bytes.Buffer, error) {
	var merged interface{}
	var hasContent bool
	for _, r := range sources {
		d := yaml.NewDecoder(bytes.NewReader(r))
		d.SetStrict(strict)

		var contents interface{}
		if err := d.Decode(&contents); err == io.EOF {
			// Skip empty and comment-only sources, which we should handle
			// differently from explicit nils.
			continue
		} else if err != nil {
			return nil, fmt.Errorf("couldn't decode source: %v", err)
		}

		hasContent = true
		pair, err := merge(merged, contents, strict)
		if err != nil {
			return nil, err // error is already descriptive enough
		}
		merged = pair
	}

	buf := &bytes.Buffer{}
	if !hasContent {
		// No sources had any content. To distinguish this from a source with just
		// an explicit top-level null, return an empty buffer.
		return buf, nil
	}
	enc := yaml.NewEncoder(buf)
	if err := enc.Encode(merged); err != nil {
		return nil, errors.Wrap(err, "couldn't re-serialize merged YAML")
	}
	return buf, nil
}

func merge(into, from interface{}, strict bool) (interface{}, error) {
	// It's possible to handle this with a mass of reflection, but we only need
	// to merge whole YAML files. Since we're always unmarshaling into
	// interface{}, we only need to handle a few types. This ends up being
	// cleaner if we just handle each case explicitly.
	if into == nil {
		return from, nil
	}
	if from == nil {
		// Allow higher-priority YAML to explicitly nil out lower-priority entries.
		return nil, nil
	}
	if IsScalar(into) && IsScalar(from) {
		return from, nil
	}
	if IsSequence(into) && IsSequence(from) {
		return from, nil
	}
	if IsMapping(into) && IsMapping(from) {
		return mergeMapping(into.(mapping), from.(mapping), strict)
	}
	// YAML types don't match, so no merge is possible. For backward
	// compatibility, ignore mismatches unless we're in strict mode and return
	// the higher-priority value.
	if !strict {
		return from, nil
	}
	return nil, fmt.Errorf("can't merge a %s into a %s", describe(from), describe(into))
}

func mergeMapping(into, from mapping, strict bool) (mapping, error) {
	merged := make(mapping, len(into))
	for k, v := range into {
		merged[k] = v
	}
	for k := range from {
		m, err := merge(merged[k], from[k], strict)
		if err != nil {
			return nil, err
		}
		merged[k] = m
	}
	return merged, nil
}

// IsMapping reports whether a type is a mapping in YAML, represented as a
// map[interface{}]interface{}.
func IsMapping(i interface{}) bool {
	_, is := i.(mapping)
	return is
}

// IsSequence reports whether a type is a sequence in YAML, represented as an
// []interface{}.
func IsSequence(i interface{}) bool {
	_, is := i.(sequence)
	return is
}

// IsScalar reports whether a type is a scalar value in YAML.
func IsScalar(i interface{}) bool {
	return !IsMapping(i) && !IsSequence(i)
}

func describe(i interface{}) string {
	if IsMapping(i) {
		return "mapping"
	}
	if IsSequence(i) {
		return "sequence"
	}
	return "scalar"
}
