package exprhelpers

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonExtract(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatal(err)
	}

	tests := []struct {
		name         string
		jsonBlob     string
		targetField  string
		expectResult string
	}{
		{
			name:         "basic json extract",
			jsonBlob:     `{"test" : "1234"}`,
			targetField:  "test",
			expectResult: "1234",
		},
		{
			name:         "basic json extract with non existing field",
			jsonBlob:     `{"test" : "1234"}`,
			targetField:  "non_existing_field",
			expectResult: "",
		},
		{
			name:         "extract subfield",
			jsonBlob:     `{"test" : {"a": "b"}}`,
			targetField:  "test.a",
			expectResult: "b",
		},
	}

	for _, test := range tests {
		result, _ := JsonExtract(test.jsonBlob, test.targetField)
		isOk := assert.Equal(t, test.expectResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}
func TestJsonExtractUnescape(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatal(err)
	}

	tests := []struct {
		name         string
		jsonBlob     string
		targetField  string
		expectResult string
	}{
		{
			name:         "basic json extract",
			jsonBlob:     `{"log" : "\"GET /JBNwtQ6i.blt HTTP/1.1\" 200 13 \"-\" \"Craftbot\""}`,
			targetField:  "log",
			expectResult: "\"GET /JBNwtQ6i.blt HTTP/1.1\" 200 13 \"-\" \"Craftbot\"",
		},
		{
			name:         "basic json extract with non existing field",
			jsonBlob:     `{"test" : "1234"}`,
			targetField:  "non_existing_field",
			expectResult: "",
		},
	}

	for _, test := range tests {
		result, _ := JsonExtractUnescape(test.jsonBlob, test.targetField)
		isOk := assert.Equal(t, test.expectResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestJsonExtractSlice(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatal(err)
	}

	tests := []struct {
		name         string
		jsonBlob     string
		targetField  string
		expectResult []interface{}
	}{
		{
			name:         "try to extract a string as a slice",
			jsonBlob:     `{"test" : "1234"}`,
			targetField:  "test",
			expectResult: nil,
		},
		{
			name:         "basic json slice extract",
			jsonBlob:     `{"test" : ["1234"]}`,
			targetField:  "test",
			expectResult: []interface{}{"1234"},
		},
		{
			name:         "extract with complex expression",
			jsonBlob:     `{"test": {"foo": [{"a":"b"}]}}`,
			targetField:  "test.foo",
			expectResult: []interface{}{map[string]interface{}{"a": "b"}},
		},
		{
			name:         "extract non-existing key",
			jsonBlob:     `{"test: "11234"}`,
			targetField:  "foo",
			expectResult: nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			result, _ := JsonExtractSlice(test.jsonBlob, test.targetField)
			assert.EqualValues(t, test.expectResult, result)
		})
	}
}

func TestJsonExtractObject(t *testing.T) {
	if err := Init(nil); err != nil {
		log.Fatal(err)
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatal(err)
	}

	tests := []struct {
		name         string
		jsonBlob     string
		targetField  string
		expectResult map[string]interface{}
	}{
		{
			name:         "try to extract a string as an object",
			jsonBlob:     `{"test" : "1234"}`,
			targetField:  "test",
			expectResult: nil,
		},
		{
			name:         "basic json object extract",
			jsonBlob:     `{"test" : {"1234": {"foo": "bar"}}}`,
			targetField:  "test",
			expectResult: map[string]interface{}{"1234": map[string]interface{}{"foo": "bar"}},
		},
		{
			name:         "extract with complex expression",
			jsonBlob:     `{"test": {"foo": [{"a":"b"}]}}`,
			targetField:  "test.foo[0]",
			expectResult: map[string]interface{}{"a": "b"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			result, _ := JsonExtractObject(test.jsonBlob, test.targetField)
			assert.Equal(t, test.expectResult, result)
		})
	}
}

func TestToJson(t *testing.T) {
	tests := []struct {
		name         string
		obj          interface{}
		expectResult string
	}{
		{
			name:         "convert int",
			obj:          42,
			expectResult: "42",
		},
		{
			name:         "convert slice",
			obj:          []string{"foo", "bar"},
			expectResult: `["foo","bar"]`,
		},
		{
			name:         "convert map",
			obj:          map[string]string{"foo": "bar"},
			expectResult: `{"foo":"bar"}`,
		},
		{
			name:         "convert struct",
			obj:          struct{ Foo string }{"bar"},
			expectResult: `{"Foo":"bar"}`,
		},
		{
			name: "convert complex struct",
			obj: struct {
				Foo string
				Bar struct {
					Baz string
				}
				Bla []string
			}{
				Foo: "bar",
				Bar: struct {
					Baz string
				}{
					Baz: "baz",
				},
				Bla: []string{"foo", "bar"},
			},
			expectResult: `{"Foo":"bar","Bar":{"Baz":"baz"},"Bla":["foo","bar"]}`,
		},
		{
			name:         "convert invalid type",
			obj:          func() {},
			expectResult: "",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			result, _ := ToJson(test.obj)
			assert.Equal(t, test.expectResult, result)
		})
	}
}
