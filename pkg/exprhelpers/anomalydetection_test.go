package exprhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnomalyDetection(t *testing.T) {
	tests := []struct {
		name         string
		params       []any
		expectResult any
		err          error
	}{
		{
			name:         "Empty verb and path",
			params:       []any{"", ""},
			expectResult: 1,
			err:          nil,
		},
		{
			name:         "Empty verb",
			params:       []any{"", "/somepath"},
			expectResult: 0,
			err:          nil,
		},
		{
			name:         "Empty path",
			params:       []any{"GET", ""},
			expectResult: 0,
			err:          nil,
		},
		{
			name:         "Valid verb and path",
			params:       []any{"GET", "/somepath"},
			expectResult: 0,
			err:          nil,
		},
	}

	InitRobertaInferencePipeline("/var/models")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := AnomalyDetection(tt.params...)
			assert.Equal(t, tt.expectResult, result)
		})
	}
}
