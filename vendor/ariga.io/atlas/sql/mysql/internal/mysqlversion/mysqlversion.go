// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package mysqlversion

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

// V provides information about MySQL versions.
type V string

// SupportsCheck reports if the version supports the CHECK
// clause, and return the querying for getting them.
func (v V) SupportsCheck() bool {
	u := "8.0.16"
	if v.Maria() {
		u = "10.2.1"
	}
	return v.GTE(u)
}

// SupportsIndexExpr reports if the version supports
// index expressions (functional key part).
func (v V) SupportsIndexExpr() bool {
	return !v.Maria() && v.GTE("8.0.13")
}

// SupportsDisplayWidth reports if the version supports getting
// the display width information from the information schema.
func (v V) SupportsDisplayWidth() bool {
	// MySQL v8.0.19 dropped the display width
	// information from the information schema
	return v.Maria() || v.LT("8.0.19")
}

// SupportsExprDefault reports if the version supports
// expressions in the DEFAULT clause on column definition.
func (v V) SupportsExprDefault() bool {
	u := "8.0.13"
	if v.Maria() {
		u = "10.2.1"
	}
	return v.GTE(u)
}

// SupportsEnforceCheck reports if the version supports
// the ENFORCED option in CHECK constraint syntax.
func (v V) SupportsEnforceCheck() bool {
	return !v.Maria() && v.GTE("8.0.16")
}

// SupportsGeneratedColumns reports if the version supports
// the generated columns in information schema.
func (v V) SupportsGeneratedColumns() bool {
	u := "5.7"
	if v.Maria() {
		u = "10.2"
	}
	return v.GTE(u)
}

// SupportsRenameColumn reports if the version supports
// the "RENAME COLUMN" clause.
func (v V) SupportsRenameColumn() bool {
	u := "8"
	if v.Maria() {
		u = "10.5.2"
	}
	return v.GTE(u)
}

// SupportsIndexComment reports if the version
// supports comments on indexes.
func (v V) SupportsIndexComment() bool {
	// According to Oracle release notes, comments on
	// indexes were added in version 5.5.3.
	return v.Maria() || v.GTE("5.5.3")
}

// CharsetToCollate returns the mapping from charset to its default collation.
func (v V) CharsetToCollate() (map[string]string, error) {
	name := "is/charset2collate"
	if v.Maria() {
		name += ".maria"
	}
	return decode(name)
}

// CollateToCharset returns the mapping from a collation to its charset.
func (v V) CollateToCharset() (map[string]string, error) {
	name := "is/collate2charset"
	if v.Maria() {
		name += ".maria"
	}
	return decode(name)
}

// Maria reports if the MySQL version is MariaDB.
func (v V) Maria() bool {
	return strings.Index(string(v), "MariaDB") > 0
}

// TiDB reports if the MySQL version is TiDB.
func (v V) TiDB() bool {
	return strings.Index(string(v), "TiDB") > 0
}

// Compare returns an integer comparing two versions according to
// semantic version precedence.
func (v V) Compare(w string) int {
	u := string(v)
	switch {
	case v.Maria():
		u = u[:strings.Index(u, "MariaDB")-1]
	case v.TiDB():
		u = u[:strings.Index(u, "TiDB")-1]
	}
	return semver.Compare("v"+u, "v"+w)
}

// GTE reports if the version is >= w.
func (v V) GTE(w string) bool { return v.Compare(w) >= 0 }

// LT reports if the version is < w.
func (v V) LT(w string) bool { return v.Compare(w) == -1 }

//go:embed is/*
var encoding embed.FS

func decode(name string) (map[string]string, error) {
	f, err := encoding.Open(name)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode %q", name)
	}
	return m, nil
}
