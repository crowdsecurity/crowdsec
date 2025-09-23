package database_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func TestBatch(t *testing.T) {
	type callRecord struct {
		calledBatches [][]int
	}

	tests := []struct {
		name        string
		elems       []int
		batchSize   int
		cancelCtx   bool
		fnErrorAt   int  // number of batch where fn fails (0 = never)
		wantErr     bool
		wantBatches [][]int
	}{
		{
			name:        "normal batching",
			elems:       []int{1, 2, 3, 4, 5},
			batchSize:   2,
			wantBatches: [][]int{{1, 2}, {3, 4}, {5}},
		},
		{
			name:        "batchSize zero = all in one batch",
			elems:       []int{1, 2, 3},
			batchSize:   0,
			wantBatches: [][]int{{1, 2, 3}},
		},
		{
			name:        "batchSize > len(elems)",
			elems:       []int{1, 2, 3},
			batchSize:   10,
			wantBatches: [][]int{{1, 2, 3}},
		},
		{
			name:        "empty input",
			elems:       []int{},
			batchSize:   3,
			wantBatches: nil,
		},
		{
			name:        "nil input",
			elems:       nil,
			batchSize:   3,
			wantBatches: nil,
		},
		{
			name:        "error in fn",
			elems:       []int{1, 2, 3, 4},
			batchSize:   2,
			fnErrorAt:   2,
			wantErr:     true,
			wantBatches: [][]int{{1, 2}},
		},
		{
			name:        "context canceled before loop",
			elems:       []int{1, 2, 3},
			batchSize:   2,
			cancelCtx:   true,
			wantErr:     true,
			wantBatches: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rec callRecord
			ctx := t.Context()

			// not testing a cancel _between_ batches, this should be enough
			if tc.cancelCtx {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}

			err := database.Batch(ctx, tc.elems, tc.batchSize, func(_ context.Context, batch []int) error {
				if len(rec.calledBatches) == tc.fnErrorAt-1 {
					return errors.New("simulated error")
				}

				rec.calledBatches = append(rec.calledBatches, batch)

				return nil
			})

			switch {
			case tc.wantErr && tc.cancelCtx:
				require.ErrorContains(t, err, "context canceled")
			case tc.wantErr:
				require.ErrorContains(t, err, "simulated error")
			default:
				require.NoError(t, err)
			}

			assert.Equal(t, tc.wantBatches, rec.calledBatches)
		})
	}
}
