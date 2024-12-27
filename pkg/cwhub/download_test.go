package cwhub

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchIndex(t *testing.T) {
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("with_content") == "true" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`Hi I'm an index with content`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`Hi I'm a regular index`))
		}
	}))
	defer mockServer.Close()

	downloader := &Downloader{
		Branch:      "main",
		URLTemplate: mockServer.URL + "/%s/%s",
		IndexPath:   "index.txt",
	}

	logger := logrus.New()
	logger.Out = io.Discard

	destPath := filepath.Join(t.TempDir(), "index.txt")
	withContent := true

	downloaded, err := downloader.FetchIndex(ctx, destPath, withContent, logger)
	require.NoError(t, err)
	assert.True(t, downloaded)

	content, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, "Hi I'm an index with content", string(content))
}
