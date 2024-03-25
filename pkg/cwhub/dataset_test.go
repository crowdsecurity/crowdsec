package cwhub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestDownloadFile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xx":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "example content oneoneone")
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "not found")
		}
	}))
	defer ts.Close()

	dest := filepath.Join(t.TempDir(), "example.txt")
	defer os.Remove(dest)

	err := downloadFile(ts.URL+"/xx", dest)
	require.NoError(t, err)

	content, err := os.ReadFile(dest)
	assert.Equal(t, "example content oneoneone", string(content))
	require.NoError(t, err)

	// bad uri
	err = downloadFile("https://zz.com", dest)
	cstest.RequireErrorContains(t, err, "lookup zz.com")
	cstest.RequireErrorContains(t, err, "no such host")

	// 404
	err = downloadFile(ts.URL+"/x", dest)
	cstest.RequireErrorContains(t, err, "bad http code 404")

	// bad target
	err = downloadFile(ts.URL+"/xx", "")
	cstest.RequireErrorContains(t, err, cstest.PathNotFoundMessage)

	// destination directory does not exist
	err = downloadFile(ts.URL+"/xx", filepath.Join(t.TempDir(), "missing/example.txt"))
	cstest.RequireErrorContains(t, err, cstest.PathNotFoundMessage)
}
