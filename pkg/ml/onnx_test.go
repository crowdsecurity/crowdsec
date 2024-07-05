//go:build !nomlsupport
// +build !nomlsupport

package ml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOnnxPrediction(t *testing.T) {
	tests := []struct {
		name        string
		modelPath   string
		tokenIDs    []uint32
		inputShape  []int64
		expectError bool
	}{
		{
			name:        "Valid input",
			modelPath:   "tests/roberta-torch-export.onnx",
			tokenIDs:    []uint32{1675, 225, 649, 999},
			inputShape:  []int64{1, 256},
			expectError: false,
		},
		// {
		// 	name:        "Invalid model path",
		// 	modelPath:   "invalid/path/to/model.onnx",
		// 	tokenIDs:    []uint32{1, 2},
		// 	inputShape:  []int64{192, 256},
		// 	expectError: true,
		// },
		// {
		// 	name:        "Mismatched input shape",
		// 	modelPath:   "tests/roberta.onnx",
		// 	tokenIDs:    []uint32{34267, 21732},
		// 	inputShape:  []int64{192, 128},
		// 	expectError: true,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := PrepareInput(tt.tokenIDs, tt.inputShape)
			assert.NoError(t, err, "prepareInput should not return an error")
			res, err := OnnxPrediction(tt.modelPath, input, tt.inputShape)
			if tt.expectError {
				assert.Error(t, err, "Expected an error but didn't get one")
			} else {
				assert.NoError(t, err, "Didn't expect an error but got one")
				assert.NotNil(t, res, "Expected a non-nil result")
				if assert.Len(t, res, 1, "Expected one result tensor") {
					assert.Equal(t, []int64{1, 2}, res[0].Shape, "Output tensor shape should be [1, 2]")
				}
			}
		})
	}
}

func BenchmarkOnnxPrediction(b *testing.B) {
	modelPath := "tests/roberta-torch-export.onnx"
	tokenIDs := []uint32{1675, 225, 649, 999}
	inputShape := []int64{1, 256}
	input, err := PrepareInput(tokenIDs, inputShape)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, err := OnnxPrediction(modelPath, input, inputShape)
		if err != nil {
			b.Fatal(err)
		}
	}
}
