//go:build !nomlsupport
// +build !nomlsupport

package ml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		name           string
		inputText      string
		tokenizerPath  string
		expectedIds    []uint32
		expectedTokens []string
	}{
		{
			name:           "Tokenize 'hello world' with custom path",
			inputText:      "hello world",
			expectedIds:    []uint32{1675, 225, 649, 999},
			expectedTokens: []string{"hello", "Ġ", "wor", "ld"},
		},
	}

	tokenizer, err := NewTokenizer("tests")
	if err != nil {
		t.Errorf("NewTokenizer returned error: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, tokens, _, err := tokenizer.Encode(tt.inputText, false, false, false)

			if err != nil {
				t.Errorf("tokenize returned error: %v", err)
			}

			assert.Equal(t, tt.expectedIds, ids, "IDs do not match")
			assert.Equal(t, tt.expectedTokens, tokens, "Tokens do not match")
		})
	}
}
