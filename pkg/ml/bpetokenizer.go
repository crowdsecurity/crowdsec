//go:build !nomlsupport
// +build !nomlsupport

package ml

import (
	"fmt"
	"path/filepath"

	tokenizers "github.com/daulet/tokenizers"
)

func tokenize(text string) ([]uint32, []string, error) {
	var tk *tokenizers.Tokenizer
	var err error

	tk, err = NewBBPETokenizer("tests")
	if err != nil {
		return nil, nil, err
	}
	defer tk.Close()

	fmt.Println("Vocab size:", tk.VocabSize())
	ids, tokens := tk.Encode(text, false)
	return ids, tokens, nil
}

type Tokenizer struct {
	tk *tokenizers.Tokenizer
}

func NewBBPETokenizer(datadir string) (*tokenizers.Tokenizer, error) {
	return tokenizers.FromFile(filepath.Join(datadir, "tokenizer.json"))
}

func (t *Tokenizer) Close() {
	t.tk.Close()
}
