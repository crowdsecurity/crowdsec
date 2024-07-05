//go:build !nomlsupport
// +build !nomlsupport

package ml

// import (
// 	"fmt"

// 	tokenizers "github.com/daulet/tokenizers"
// )

// func FastTextClassifier(text string) ([]fasttext.Prediction, error) {
// 	var tk *tokenizers.Tokenizer
// 	var err error
// 	var path string

// 	if len(tokenizerJSONPath) > 0 && tokenizerJSONPath[0] != "" {
// 		path = tokenizerJSONPath[0]
// 	} else {
// 		path = "tests/tokenizer.json"
// 	}

// 	tk, err = NewBBPETokenizer(path)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	defer tk.Close()

// 	text := tokens.Join([]string, " ")

// 	fmt.Println("Vocab size:", tk.VocabSize())
// 	ids, tokens := tk.Encode(text, false)
// 	return ft.PredictLabel(concatenatedTokens, k, threshold)
// }
