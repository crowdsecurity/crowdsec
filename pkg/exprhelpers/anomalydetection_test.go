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
			params:       []any{"", "hello"},
			expectResult: false,
			err:          nil,
		},
		{
			name:         "Empty verb",
			params:       []any{"", "/somepath"},
			expectResult: false,
			err:          nil,
		},
		{
			name:         "Empty path",
			params:       []any{"GET", ""},
			expectResult: true,
			err:          nil,
		},
		{
			name:         "Valid verb and path",
			params:       []any{"GET", "/somepath"},
			expectResult: false,
			err:          nil,
		},
	}

	tarFilePath := "testdata/anomaly_detection_bundle_test.tar"

	if err := InitRobertaInferencePipeline(tarFilePath); err != nil {
		t.Fatalf("failed to initialize RobertaInferencePipeline: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := IsAnomalous(tt.params...)
			assert.Equal(t, tt.expectResult, result)
		})
	}
}
