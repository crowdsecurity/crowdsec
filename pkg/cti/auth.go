package cti

import (
	"context"
	"net/http"
)

func APIKeyInserter(apiKey string) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Add("x-api-key", apiKey)
		return nil
	}
}

