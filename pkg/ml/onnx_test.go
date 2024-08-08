//go:build !nomlsupport
// +build !nomlsupport

package ml

import (
	"testing"

	onnxruntime "github.com/crowdsecurity/go-onnxruntime"
	"github.com/stretchr/testify/assert"
)

func TestOnnxPrediction(t *testing.T) {
	tests := []struct {
		name          string
		modelPath     string
		tokenIDs      []int64
		attentionMask []int64
		inputShape    []int64
		expectError   bool
	}{
		{
			name:          "Valid input",
			modelPath:     "tests/roberta-torch-export.onnx",
			tokenIDs:      []int64{1675, 225, 649, 999},
			attentionMask: []int64{1, 1, 1, 1},
			inputShape:    []int64{1, 256},
			expectError:   false,
		},
		{
			name:          "Valid input",
			modelPath:     "tests/roberta-torch-export.onnx",
			tokenIDs:      []int64{1675, 1111, 649, 999},
			attentionMask: []int64{1, 1, 1, 1},
			inputShape:    []int64{1, 256},
			expectError:   false,
		},
	}

	ortSession, err := NewOrtSession("tests/model.onnx")
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ortSession.PredictLabel([]onnxruntime.TensorValue{
				GetTensorValue(tt.tokenIDs, tt.inputShape),
				GetTensorValue(tt.attentionMask, tt.inputShape),
			})
			assert.NoError(t, err, "prepareInput should not return an error")
			if tt.expectError {
				assert.Error(t, err, "Expected an error but didn't get one")
			} else {
				assert.NoError(t, err, "Didn't expect an error but got one")
				assert.NotNil(t, res, "Expected a non-nil result")
			}
		})
	}
}
