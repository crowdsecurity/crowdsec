//go:build !no_mlsupport

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

	// check if tokenizer.json exists
	tokenizerPath := filepath.Join(datadir, "tokenizer.json")
	if _, err := os.Stat(tokenizerPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("tokenizer.json not found in %s", datadir)
	}

	tk, err := tokenizers.FromFile(tokenizerPath)
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

type EncodeOptions struct {
	AddSpecialTokens    bool
	PadToMaxLength      bool
	ReturnAttentionMask bool
	Truncate            bool
}

func (t *Tokenizer) Encode(text string, options EncodeOptions) ([]int64, []string, []int64, error) {
	if t.tk == nil {
		return nil, nil, nil, fmt.Errorf("tokenizer is not initialized")
	}

	ids, tokens := t.tk.Encode(text, options.AddSpecialTokens)

	// Truncate to max length (right truncation)
	if len(ids) > t.modelMaxLength && options.Truncate {
		ids = ids[:t.modelMaxLength]
		tokens = tokens[:t.modelMaxLength]
	}

	//[]uint32 to []int64
	int64Ids := make([]int64, len(ids))
	for i, id := range ids {
		int64Ids[i] = int64(id)
	}

	// Padding to max length
	if options.PadToMaxLength && len(int64Ids) < t.modelMaxLength {
		paddingLength := t.modelMaxLength - len(int64Ids)
		for i := 0; i < paddingLength; i++ {
			int64Ids = append(int64Ids, int64(t.padTokenID))
			tokens = append(tokens, "<pad>")
		}
	}

	// Creating attention mask
	var attentionMask []int64
	if options.ReturnAttentionMask {
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
