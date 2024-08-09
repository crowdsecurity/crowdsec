//go:build !nomlsupport
// +build !nomlsupport

package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	tokenizers "github.com/daulet/tokenizers"
)

type Tokenizer struct {
	tk             *tokenizers.Tokenizer
	modelMaxLength int
	padTokenID     int
	tokenizerClass string
}

type tokenizerConfig struct {
	ModelMaxLen       int                               `json:"model_max_length"`
	PadToken          string                            `json:"pad_token"`
	TokenizerClass    string                            `json:"tokenizer_class"`
	AddedTokenDecoder map[string]map[string]interface{} `json:"added_tokens_decoder"`
}

func loadTokenizerConfig(filename string) (*tokenizerConfig, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading tokenizer config file")
		return nil, err
	}
	config := &tokenizerConfig{}
	if err := json.Unmarshal(file, config); err != nil {
		fmt.Println("Error unmarshalling tokenizer config")
		return nil, err
	}
	return config, nil
}

func findTokenID(tokens map[string]map[string]interface{}, tokenContent string) int {
	for key, value := range tokens {
		if content, ok := value["content"]; ok && content == tokenContent {
			if tokenID, err := strconv.Atoi(key); err == nil {
				return tokenID
			}
		}
	}
	return -1
}

func NewTokenizer(datadir string) (*Tokenizer, error) {
	defaultMaxLen := 512
	defaultPadTokenID := 1
	defaultTokenizerClass := "RobertaTokenizer"

	tk, err := tokenizers.FromFile(filepath.Join(datadir, "tokenizer.json"))
	if err != nil {
		return nil, err
	}

	configFile := filepath.Join(datadir, "tokenizer_config.json")
	config, err := loadTokenizerConfig(configFile)
	if err != nil {
		fmt.Println("Warning: Could not load tokenizer config, using default values.")
		return &Tokenizer{
			tk:             tk,
			modelMaxLength: defaultMaxLen,
			padTokenID:     defaultPadTokenID,
			tokenizerClass: defaultTokenizerClass,
		}, nil
	}

	// Use default values if any required config is missing
	// modelMaxLen := 256
	modelMaxLen := config.ModelMaxLen
	if modelMaxLen == 0 {
		modelMaxLen = defaultMaxLen
	}

	padTokenID := findTokenID(config.AddedTokenDecoder, config.PadToken)
	if padTokenID == -1 {
		padTokenID = defaultPadTokenID
	}

	tokenizerClass := config.TokenizerClass
	if tokenizerClass == "" {
		tokenizerClass = defaultTokenizerClass
	}

	return &Tokenizer{
		tk:             tk,
		modelMaxLength: modelMaxLen,
		padTokenID:     padTokenID,
		tokenizerClass: tokenizerClass,
	}, nil
}

func (t *Tokenizer) Encode(text string, addSpecialTokens, padToMaxLength, returnAttentionMask bool) ([]int64, []string, []int64, error) {
	if t.tk == nil {
		return nil, nil, nil, fmt.Errorf("tokenizer is not initialized")
	}

	ids, tokens := t.tk.Encode(text, addSpecialTokens)

	// Truncate to max length (left)
	ids = ids[len(ids)-t.modelMaxLength:]
	tokens = tokens[len(tokens)-t.modelMaxLength:]

	//[]uint32 to []int64
	int64Ids := make([]int64, len(ids))
	for i, id := range ids {
		int64Ids[i] = int64(id)
	}

	// Padding to max length
	if padToMaxLength && len(int64Ids) < t.modelMaxLength {
		paddingLength := t.modelMaxLength - len(int64Ids)
		for i := 0; i < paddingLength; i++ {
			int64Ids = append(int64Ids, int64(t.padTokenID))
			tokens = append(tokens, "<pad>")
		}
	}

	// Creating attention mask
	var attentionMask []int64
	if returnAttentionMask {
		attentionMask = make([]int64, len(int64Ids))
		for i := range attentionMask {
			if int64Ids[i] != int64(t.padTokenID) {
				attentionMask[i] = 1
			} else {
				attentionMask[i] = 0
			}
		}
	}

	return int64Ids, tokens, attentionMask, nil
}

func (t *Tokenizer) Close() {
	t.tk.Close()
}

func BpeTesting() {
	// tk, _ := NewTokenizer("/Users/davidlequin/models")
	// defer tk.Close()
	// ids, _ := tk.tk.Encode("hello world", true)
	// fmt.Println(ids)
	// ids, _, attentionMask, _ := tk.Encode("hello world", false, true, true)
	// fmt.Println("Token IDs:", ids)
	// fmt.Println("Attention Mask:", attentionMask)
	// // config, _ := loadTokenizerConfig("tests/tokenizer_config.json")
	// // fmt.Println(config)
	// fmt.Println(tk)
}
