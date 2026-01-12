package types

import (
	"strings"

)

// Move in leakybuckets
const (
	Undefined = ""
	Ip        = "Ip"
	Range     = "Range"
	Filter    = "Filter"
	Country   = "Country"
	AS        = "AS"
)

func NormalizeScope(scope string) string {
	switch strings.ToLower(scope) {
	case "ip":
		return Ip
	case "range":
		return Range
	case "as":
		return AS
	case "country":
		return Country
	default:
		return scope
	}
}
