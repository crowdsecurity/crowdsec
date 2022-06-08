package exprhelpers

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonExtract(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatalf(err.Error())
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
	}

	for _, test := range tests {
		result := JsonExtract(test.jsonBlob, test.targetField)
		isOk := assert.Equal(t, test.expectResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}
func TestJsonExtractUnescape(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatalf(err.Error())
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
		result := JsonExtractUnescape(test.jsonBlob, test.targetField)
		isOk := assert.Equal(t, test.expectResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}
}

func TestJsonExtractSlice(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatalf(err.Error())
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := JsonExtractSlice(test.jsonBlob, test.targetField)
			assert.Equal(t, test.expectResult, result)
		})
	}
}

func TestJsonExtractObject(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatalf(err.Error())
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := JsonExtractObject(test.jsonBlob, test.targetField)
			assert.Equal(t, test.expectResult, result)
		})
	}
}
