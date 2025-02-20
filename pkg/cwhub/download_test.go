package cwhub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestFetchIndex(t *testing.T) {
	ctx := t.Context()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main/.index.json" {
			w.WriteHeader(http.StatusNotFound)
		}

		if r.URL.Query().Get("with_content") == "true" {
			_, err := w.Write([]byte(`Hi I'm an index with content`))
			assert.NoError(t, err)
		} else {
			_, err := w.Write([]byte(`Hi I'm a minified index`))
			assert.NoError(t, err)
		}
	}))
	defer mockServer.Close()

	discard := logrus.New()
	discard.Out = io.Discard

	downloader := &Downloader{
		URLTemplate: mockServer.URL + "/%s/%s",
	}

	destPath := filepath.Join(t.TempDir(), "index-here")
	withContent := true

	var notFoundError NotFoundError

	// bad branch

	downloader.Branch = "dev"

	downloaded, err := downloader.FetchIndex(ctx, destPath, withContent, discard)
	require.ErrorAs(t, err, &notFoundError)
	assert.False(t, downloaded)

	// ok

	downloader.Branch = "main"

	downloaded, err = downloader.FetchIndex(ctx, destPath, withContent, discard)
	require.NoError(t, err)
	assert.True(t, downloaded)

	content, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, "Hi I'm an index with content", string(content))

	// not "downloading" a second time
	// since we don't have cache control in the mockServer,
	// the file is downloaded to a temporary location but not replaced

	downloaded, err = downloader.FetchIndex(ctx, destPath, withContent, discard)
	require.NoError(t, err)
	assert.False(t, downloaded)

	// download without item content

	downloaded, err = downloader.FetchIndex(ctx, destPath, !withContent, discard)
	require.NoError(t, err)
	assert.True(t, downloaded)

	content, err = os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, "Hi I'm a minified index", string(content))

	// bad domain name

	downloader.URLTemplate = "x/%s/%s"
	downloaded, err = downloader.FetchIndex(ctx, destPath, !withContent, discard)
	cstest.AssertErrorContains(t, err, `Get "x/main/.index.json": unsupported protocol scheme ""`)
	assert.False(t, downloaded)

	downloader.URLTemplate = "http://x/%s/%s"
	downloaded, err = downloader.FetchIndex(ctx, destPath, !withContent, discard)
	// can be no such host, server misbehaving, etc
	cstest.AssertErrorContains(t, err, `Get "http://x/main/.index.json": dial tcp: lookup x`)
	assert.False(t, downloaded)
}

func TestFetchContent(t *testing.T) {
	ctx := t.Context()
	wantContent := "{'description':'linux'}"
	wantHash := "e557cb9e1cb051bc3b6a695e4396c5f8e0eff4b7b0d2cc09f7684e1d52ea2224"
	remotePath := "collections/crowdsecurity/linux.yaml"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main/"+remotePath {
			w.WriteHeader(http.StatusNotFound)
		}

		_, err := w.Write([]byte(wantContent))
		assert.NoError(t, err)
	}))
	defer mockServer.Close()

	wantURL := mockServer.URL + "/main/collections/crowdsecurity/linux.yaml"

	// bad branch

	hubDownloader := &Downloader{
		URLTemplate: mockServer.URL + "/%s/%s",
	}

	discard := logrus.New()
	discard.Out = io.Discard

	destPath := filepath.Join(t.TempDir(), "content-here")

	var notFoundError NotFoundError

	// bad branch

	hubDownloader.Branch = "dev"

	downloaded, url, err := hubDownloader.FetchContent(ctx, remotePath, destPath, wantHash, discard)
	assert.Empty(t, url)
	require.ErrorAs(t, err, &notFoundError)
	assert.False(t, downloaded)

	// bad path

	hubDownloader.Branch = "main"

	downloaded, url, err = hubDownloader.FetchContent(ctx, "collections/linux.yaml", destPath, wantHash, discard)
	assert.Empty(t, url)
	require.ErrorAs(t, err, &notFoundError)
	assert.False(t, downloaded)

	// hash mismatch: the file is not reported as downloaded because it's not replaced

	capture, hook := logtest.NewNullLogger()
	capture.SetLevel(logrus.WarnLevel)

	downloaded, url, err = hubDownloader.FetchContent(ctx, remotePath, destPath, "1234", capture)
	assert.Equal(t, wantURL, url)
	require.NoError(t, err)
	assert.False(t, downloaded)
	cstest.RequireLogContains(t, hook, "hash mismatch: expected 1234, got "+wantHash)

	// ok

	downloaded, url, err = hubDownloader.FetchContent(ctx, remotePath, destPath, wantHash, discard)
	assert.Equal(t, wantURL, url)
	require.NoError(t, err)
	assert.True(t, downloaded)

	content, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, wantContent, string(content))

	// not "downloading" a second time
	// since we don't have cache control in the mockServer,
	// the file is downloaded to a temporary location but not replaced

	downloaded, url, err = hubDownloader.FetchContent(ctx, remotePath, destPath, wantHash, discard)
	assert.Equal(t, wantURL, url)
	require.NoError(t, err)
	assert.False(t, downloaded)
}
