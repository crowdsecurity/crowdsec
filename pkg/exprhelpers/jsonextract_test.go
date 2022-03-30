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
