package exprhelpers

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected url.Values
	}{
		{
			name:  "Full URI",
			query: "/foobar/toto?ab=cd&ef=gh",
			expected: url.Values{
				"/foobar/toto?ab": []string{"cd"},
				"ef":              []string{"gh"},
			},
		},
		{
			name:  "Simple query",
			query: "foo=bar",
			expected: url.Values{
				"foo": []string{"bar"},
			},
		},
		{
			name:  "Multiple values",
			query: "foo=bar&foo=baz",
			expected: url.Values{
				"foo": []string{"bar", "baz"},
			},
		},
		{
			name:  "Empty value",
			query: "foo=",
			expected: url.Values{
				"foo": []string{""},
			},
		},
		{
			name:  "Empty key",
			query: "=bar",
			expected: url.Values{
				"": []string{"bar"},
			},
		},
		{
			name:     "Empty query",
			query:    "",
			expected: url.Values{},
		},
		{
			name:  "Multiple keys",
			query: "foo=bar&baz=qux",
			expected: url.Values{
				"foo": []string{"bar"},
				"baz": []string{"qux"},
			},
		},
		{
			name:  "Multiple keys with empty value",
			query: "foo=bar&baz=qux&quux=",
			expected: url.Values{
				"foo":  []string{"bar"},
				"baz":  []string{"qux"},
				"quux": []string{""},
			},
		},
		{
			name:  "Multiple keys with empty value and empty key",
			query: "foo=bar&baz=qux&quux=&=quuz",
			expected: url.Values{
				"foo":  []string{"bar"},
				"baz":  []string{"qux"},
				"quux": []string{""},
				"":     []string{"quuz"},
			},
		},
		{
			name:  "Multiple keys with empty value and empty key and multiple values",
			query: "foo=bar&baz=qux&quux=&=quuz&foo=baz",
			expected: url.Values{
				"foo":  []string{"bar", "baz"},
				"baz":  []string{"qux"},
				"quux": []string{""},
				"":     []string{"quuz"},
			},
		},
		{
			name:  "Multiple keys with empty value and empty key and multiple values and escaped characters",
			query: "foo=bar&baz=qux&quux=&=quuz&foo=baz&foo=bar%20baz",
			expected: url.Values{
				"foo":  []string{"bar", "baz", "bar baz"},
				"baz":  []string{"qux"},
				"quux": []string{""},
				"":     []string{"quuz"},
			},
		},
		{
			name:  "Multiple keys with empty value and empty key and multiple values and escaped characters and semicolon",
			query: "foo=bar&baz=qux&quux=&=quuz&foo=baz&foo=bar%20baz&foo=bar%3Bbaz",
			expected: url.Values{
				"foo":  []string{"bar", "baz", "bar baz", "bar;baz"},
				"baz":  []string{"qux"},
				"quux": []string{""},
				"":     []string{"quuz"},
			},
		},
		{
			name:  "Multiple keys with empty value and empty key and multiple values and escaped characters and semicolon and ampersand",
			query: "foo=bar&baz=qux&quux=&=quuz&foo=baz&foo=bar%20baz&foo=bar%3Bbaz&foo=bar%26baz",
			expected: url.Values{
				"foo":  []string{"bar", "baz", "bar baz", "bar;baz", "bar&baz"},
				"baz":  []string{"qux"},
				"quux": []string{""},
				"":     []string{"quuz"},
			},
		},
		{
			name:  "Multiple keys with empty value and empty key and multiple values and escaped characters and semicolon and ampersand and equals",
			query: "foo=bar&baz=qux&quux=&=quuz&foo=baz&foo=bar%20baz&foo=bar%3Bbaz&foo=bar%26baz&foo=bar%3Dbaz",
			expected: url.Values{
				"foo":  []string{"bar", "baz", "bar baz", "bar;baz", "bar&baz", "bar=baz"},
				"baz":  []string{"qux"},
				"quux": []string{""},
				"":     []string{"quuz"},
			},
		},
		{
			name:  "Multiple keys with empty value and empty key and multiple values and escaped characters and semicolon and ampersand and equals and question mark",
			query: "foo=bar&baz=qux&quux=&=quuz&foo=baz&foo=bar%20baz&foo=bar%3Bbaz&foo=bar%26baz&foo=bar%3Dbaz&foo=bar%3Fbaz",
			expected: url.Values{
				"foo":  []string{"bar", "baz", "bar baz", "bar;baz", "bar&baz", "bar=baz", "bar?baz"},
				"baz":  []string{"qux"},
				"quux": []string{""},
				"":     []string{"quuz"},
			},
		},
		{
			name:  "keys with escaped characters",
			query: "foo=ba;r&baz=qu;;x&quux=x\\&ww&xx=qu?uz&",
			expected: url.Values{
				"foo":  []string{"ba;r"},
				"baz":  []string{"qu;;x"},
				"quux": []string{"x\\"},
				"ww":   []string{""},
				"xx":   []string{"qu?uz"},
			},
		},
		{
			name:  "hexadecimal characters",
			query: "foo=bar%20baz",
			expected: url.Values{
				"foo": []string{"bar baz"},
			},
		},
		{
			name:  "hexadecimal characters upper and lower case",
			query: "foo=Ba%42%42&bar=w%2f%2F",
			expected: url.Values{
				"foo": []string{"BaBB"},
				"bar": []string{"w//"},
			},
		},
		{
			name:  "hexadecimal characters with invalid characters",
			query: "foo=bar%20baz%2",
			expected: url.Values{
				"foo": []string{"bar baz%2"},
			},
		},
		{
			name:  "hexadecimal characters with invalid hex characters",
			query: "foo=bar%xx",
			expected: url.Values{
				"foo": []string{"bar%xx"},
			},
		},
		{
			name:  "hexadecimal characters with invalid 2nd hex character",
			query: "foo=bar%2x",
			expected: url.Values{
				"foo": []string{"bar%2x"},
			},
		},
		{
			name:  "url +",
			query: "foo=bar+x",
			expected: url.Values{
				"foo": []string{"bar x"},
			},
		},
		{
			name:  "url &&",
			query: "foo=bar&&lol=bur",
			expected: url.Values{
				"foo": []string{"bar"},
				"lol": []string{"bur"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := ParseQuery(test.query)
			if !reflect.DeepEqual(res, test.expected) {
				t.Fatalf("unexpected result: %v", res)
			}
		})
	}
}

func TestExtractQueryParam(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		param    string
		expected []string
	}{
		{
			name:     "Simple uri",
			query:    "/foobar/toto?ab=cd&ef=gh",
			param:    "ab",
			expected: []string{"cd"},
		},
		{
			name:     "Simple uri, repeating param",
			query:    "/foobar?foo=bar&foo=baz",
			param:    "foo",
			expected: []string{"bar", "baz"},
		},
		{
			name:     "Simple uri with semicolon",
			query:    "/foobar/toto?ab=cd;ef=gh",
			param:    "ab",
			expected: []string{"cd;ef=gh"},
		},
		{
			name:     "Simple query no uri",
			query:    "foo=bar",
			param:    "foo",
			expected: []string{},
		},
		{
			name:     "No QS",
			query:    "/foobar",
			param:    "foo",
			expected: []string{},
		},
		{
			name:     "missing param",
			query:    "/foobar/toto?ab=cd&ef=gh",
			param:    "baz",
			expected: []string{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := ExtractQueryParam(test.query, test.param)
			if !reflect.DeepEqual(res, test.expected) {
				t.Fatalf("unexpected result: %v", res)
			}
		})
	}
}

func TestJA4H(t *testing.T) {

	tests := []struct {
		name         string
		method       string
		url          string
		cookies      map[string]string
		headers      map[string]string
		expectedHash string
	}{
		{
			name:         "Basic GET - No cookies",
			method:       "GET",
			url:          "http://example.com",
			cookies:      map[string]string{},
			headers:      map[string]string{},
			expectedHash: "ge11nn000000_e3b0c44298fc_000000000000_000000000000",
		},
		{
			name:         "Basic POST - No cookies",
			method:       "POST",
			url:          "http://example.com",
			cookies:      map[string]string{},
			headers:      map[string]string{},
			expectedHash: "po11nn000000_e3b0c44298fc_000000000000_000000000000",
		},
		{
			name:   "GET - With cookies",
			method: "GET",
			url:    "http://example.com/foobar",
			cookies: map[string]string{
				"foo": "bar",
				"baz": "qux",
			},
			headers: map[string]string{
				"User-Agent": "Mozilla/5.0",
			},
			expectedHash: "ge11cn010000_b8bcd45ac095_bd87575d11f6_d401f362552e",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(test.method, test.url, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %s", err)
			}

			for key, value := range test.cookies {
				req.AddCookie(&http.Cookie{
					Name:  key,
					Value: value,
				})
			}

			for key, value := range test.headers {
				req.Header.Add(key, value)
			}

			hash, err := JA4H(req)
			require.NoError(t, err)

			if hash != test.expectedHash {
				t.Fatalf("JA4H returned unexpected hash: %s", hash)
			}
		})
	}

}
