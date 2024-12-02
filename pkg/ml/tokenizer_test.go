//go:build !no_mlsupport

package ml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		name             string
		inputText        string
		tokenizerPath    string
		encodeOptions    EncodeOptions
		expectedIds      []int64
		expectedTokens   []string
		expectedMask     []int64
		expectTruncation bool
	}{
		{
			name:          "Tokenize 'this is some text'",
			inputText:     "this is some text",
			tokenizerPath: "tests/small-champion-model",
			encodeOptions: EncodeOptions{
				AddSpecialTokens:    true,
				PadToMaxLength:      false,
				ReturnAttentionMask: true,
				Truncate:            true,
			},
			expectedIds:    []int64{0, 435, 774, 225, 774, 225, 501, 334, 225, 268, 488, 2},
			expectedTokens: []string{"<s>", "th", "is", "Ġ", "is", "Ġ", "so", "me", "Ġ", "te", "xt", "</s>"},
			expectedMask:   []int64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
		{
			name:          "Tokenize 'this is some new texts'",
			inputText:     "this is some new texts",
			tokenizerPath: "tests/small-champion-model",
			encodeOptions: EncodeOptions{
				AddSpecialTokens:    true,
				PadToMaxLength:      false,
				ReturnAttentionMask: true,
				Truncate:            true,
			},
			expectedIds:    []int64{0, 435, 774, 225, 774, 225, 501, 334, 225, 1959, 225, 268, 488, 87, 2},
			expectedTokens: []string{"<s>", "th", "is", "Ġ", "is", "Ġ", "so", "me", "Ġ", "new", "Ġ", "te", "xt", "s", "</s>"},
			expectedMask:   []int64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	tokenizer, err := NewTokenizer("tests")
	if err != nil {
		t.Errorf("NewTokenizer returned error: %v", err)
		return
	}
	defer tokenizer.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, tokens, attentionMask, err := tokenizer.Encode(tt.inputText, tt.encodeOptions)

			if err != nil {
				t.Errorf("Encode returned error: %v", err)
			}

			assert.Equal(t, tt.expectedIds, ids, "IDs do not match")
			assert.Equal(t, tt.expectedTokens, tokens, "Tokens do not match")
			if tt.encodeOptions.ReturnAttentionMask {
				assert.Equal(t, tt.expectedMask, attentionMask, "Attention mask does not match")
			}
		})
	}
}

func TestTokenizeLongString(t *testing.T) {
	var builder strings.Builder
	for i := 0; i < 1024; i++ {
		builder.WriteString("a")
	}
	longString := builder.String()

	tokenizer, err := NewTokenizer("tests")
	if err != nil {
		t.Errorf("NewTokenizer returned error: %v", err)
		return
	}
	defer tokenizer.Close()

	encodeOptions := EncodeOptions{
		AddSpecialTokens:    true,
		PadToMaxLength:      false,
		ReturnAttentionMask: true,
		Truncate:            true,
	}

	ids, tokens, _, err := tokenizer.Encode(longString, encodeOptions)
	if err != nil {
		t.Errorf("Encode returned error: %v", err)
	}

	assert.Equal(t, 512, len(ids), "IDs length does not match for long string with truncation")
	assert.Equal(t, 512, len(tokens), "IDs length does not match for long string with truncation")
}
