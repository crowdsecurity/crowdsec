package database

import "context"

// Batch applies fn to successive chunks of elements, each of size at most batchSize.
// A batchSize of 0 processes all the elements in one chunk.
// Stops at the first error and returns it.
func Batch[T any](ctx context.Context, elems []T, batchSize int, fn func(context.Context, []T) error) error {
	n := len(elems)

	if n == 0 {
		return nil
	}

	if batchSize <= 0 || batchSize > n {
		batchSize = n
	}

	for start := 0; start < n; start += batchSize {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		end := min(start+batchSize, n)
		if err := fn(ctx, elems[start:end]); err != nil {
			return err
		}
	}

	return nil
}
