package exprhelpers

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXMLGetAttributeValue(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	tests := []struct {
		name         string
		xmlString    string
		path         string
		attribute    string
		expectResult string
	}{
		{
			name:         "XMLGetAttributeValue",
			xmlString:    `<root><child attr="value"/></root>`,
			path:         "/root/child",
			attribute:    "attr",
			expectResult: "value",
		},
		{
			name:         "Non existing attribute for XMLGetAttributeValue",
			xmlString:    `<root><child attr="value"/></root>`,
			path:         "/root/child",
			attribute:    "asdasd",
			expectResult: "",
		},
		{
			name:         "Non existing path for XMLGetAttributeValue",
			xmlString:    `<root><child attr="value"/></root>`,
			path:         "/foo/bar",
			attribute:    "asdasd",
			expectResult: "",
		},
		{
			name:         "Invalid XML for XMLGetAttributeValue",
			xmlString:    `<root><`,
			path:         "/foo/bar",
			attribute:    "asdasd",
			expectResult: "",
		},
		{
			name:         "Invalid path for XMLGetAttributeValue",
			xmlString:    `<root><child attr="value"/></root>`,
			path:         "/foo/bar[@",
			attribute:    "asdasd",
			expectResult: "",
		},
	}

	for _, test := range tests {
		result := XMLGetAttributeValue(test.xmlString, test.path, test.attribute)
		isOk := assert.Equal(t, test.expectResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}
func TestXMLGetNodeValue(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	tests := []struct {
		name         string
		xmlString    string
		path         string
		expectResult string
	}{
		{
			name:         "XMLGetNodeValue",
			xmlString:    `<root><child>foobar</child></root>`,
			path:         "/root/child",
			expectResult: "foobar",
		},
		{
			name:         "Non existing path for XMLGetNodeValue",
			xmlString:    `<root><child>foobar</child></root>`,
			path:         "/foo/bar",
			expectResult: "",
		},
		{
			name:         "Invalid XML for XMLGetNodeValue",
			xmlString:    `<root><`,
			path:         "/foo/bar",
			expectResult: "",
		},
		{
			name:         "Invalid path for XMLGetNodeValue",
			xmlString:    `<root><child>foobar</child></root>`,
			path:         "/foo/bar[@",
			expectResult: "",
		},
	}

	for _, test := range tests {
		result := XMLGetNodeValue(test.xmlString, test.path)
		isOk := assert.Equal(t, test.expectResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}
