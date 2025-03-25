package exprhelpers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/ja4h"
)

// JA4H(req *http.Request) string
func JA4H(params ...any) (any, error) {
	req := params[0].(*http.Request)
	return ja4h.JA4H(req), nil
}

// just a expr wrapper for ParseQuery
func ExprWrapParseQuery(params ...any) (any, error) {
	query := params[0].(string)
	return ParseQuery(query), nil
}

// parseQuery and parseQuery are copied net/url package, but allow semicolon in values
func ParseQuery(query string) url.Values {
	m := make(url.Values)
	ParseQueryIntoValues(m, query)
	return m
}

func ParseQueryIntoValues(m url.Values, query string) {
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

// just a expr wrapper for ExtractQueryParam
func ExprWrapExtractQueryParam(params ...any) (any, error) {
	uri := params[0].(string)
	param := params[1].(string)
	return ExtractQueryParam(uri, param), nil
}

// ExtractQueryParam extracts values for a given query parameter from a raw URI string.
func ExtractQueryParam(uri, param string) []string {
	// Find the first occurrence of "?"
	idx := strings.Index(uri, "?")
	if idx == -1 {
		// No query string present
		return []string{}
	}

	// Extract the query string part
	queryString := uri[idx+1:]

	// Parse the query string using a function that supports both `&` and `;`
	values := ParseQuery(queryString)

	if values == nil {
		// No query string present
		return []string{}
	}
	// Retrieve the values for the specified parameter
	if _, ok := values[param]; !ok {
		return []string{}
	}
	return values[param]
}
