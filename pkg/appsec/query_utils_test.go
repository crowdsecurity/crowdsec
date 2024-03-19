package appsec

import (
	"net/url"
	"reflect"
	"testing"
)

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected url.Values
	}{
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
