package appsec

// This file is mostly stolen from net/url package, but with some modifications to allow less strict parsing of query strings

import (
	"net/url"
	"strings"
)

// parseQuery and parseQuery are copied net/url package, but allow semicolon in values
func ParseQuery(query string) url.Values {
	m := make(url.Values)
	parseQuery(m, query)
	return m
}

func parseQuery(m url.Values, query string) {
	for query != "" {
		var key string
		key, query, _ = strings.Cut(query, "&")

		if key == "" {
			continue
		}
		key, value, _ := strings.Cut(key, "=")
		//for now we'll just ignore the errors, but ideally we want to fire some "internal" rules when we see invalid query strings
		key = unescape(key)
		value = unescape(value)
		m[key] = append(m[key], value)
	}
}

func hexDigitToByte(digit byte) (byte, bool) {
	switch {
	case digit >= '0' && digit <= '9':
		return digit - '0', true
	case digit >= 'a' && digit <= 'f':
		return digit - 'a' + 10, true
	case digit >= 'A' && digit <= 'F':
		return digit - 'A' + 10, true
	default:
		return 0, false
	}
}

func unescape(input string) string {
	ilen := len(input)
	res := strings.Builder{}
	res.Grow(ilen)
	for i := 0; i < ilen; i++ {
		ci := input[i]
		if ci == '+' {
			res.WriteByte(' ')
			continue
		}
		if ci == '%' {
			if i+2 >= ilen {
				res.WriteByte(ci)
				continue
			}
			hi, ok := hexDigitToByte(input[i+1])
			if !ok {
				res.WriteByte(ci)
				continue
			}
			lo, ok := hexDigitToByte(input[i+2])
			if !ok {
				res.WriteByte(ci)
				continue
			}
			res.WriteByte(hi<<4 | lo)
			i += 2
			continue
		}
		res.WriteByte(ci)
	}
	return res.String()
}
