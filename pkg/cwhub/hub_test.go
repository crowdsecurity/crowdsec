package cwhub

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// testHubCfg creates an empty hub structure in a temporary directory
// and returns its configuration object.
//
// This allow the reuse of the hub content for multiple instances
// of the Hub object.
func testHubCfg(t *testing.T) *csconfig.LocalHubCfg {
	tempDir := t.TempDir()

	local := csconfig.LocalHubCfg{
		HubDir:         filepath.Join(tempDir, "crowdsec", "hub"),
		HubIndexFile:   filepath.Join(tempDir, "crowdsec", "hub", ".index.json"),
		InstallDir:     filepath.Join(tempDir, "crowdsec"),
		InstallDataDir: filepath.Join(tempDir, "installed-data"),
	}

	err := os.MkdirAll(local.HubDir, 0o755)
	require.NoError(t, err)

	err = os.MkdirAll(local.InstallDir, 0o755)
	require.NoError(t, err)

	err = os.MkdirAll(local.InstallDataDir, 0o755)
	require.NoError(t, err)

	return &local
}

func testHub(t *testing.T, localCfg *csconfig.LocalHubCfg, indexJson string) (*Hub, error) {
	if localCfg == nil {
		localCfg = testHubCfg(t)
	}

	err := os.WriteFile(localCfg.HubIndexFile, []byte(indexJson), 0o644)
	require.NoError(t, err)

	hub, err := NewHub(localCfg, nil)
	require.NoError(t, err)
	err = hub.Load()

	return hub, err
}

func TestIndexEmpty(t *testing.T) {
	// an empty hub is valid, and should not have warnings
	hub, err := testHub(t, nil, "{}")
	require.NoError(t, err)
	assert.Empty(t, hub.Warnings)
}

func TestIndexJSON(t *testing.T) {
	// but it can't be an empty string
	hub, err := testHub(t, nil, "")
	cstest.RequireErrorContains(t, err, "invalid hub index: failed to parse index: unexpected end of JSON input")
	assert.Empty(t, hub.Warnings)

	// it must be valid json
	hub, err = testHub(t, nil, "def not json")
	cstest.RequireErrorContains(t, err, "invalid hub index: failed to parse index: invalid character 'd' looking for beginning of value. Run 'sudo cscli hub update' to download the index again")
	assert.Empty(t, hub.Warnings)

	hub, err = testHub(t, nil, "{")
	cstest.RequireErrorContains(t, err, "invalid hub index: failed to parse index: unexpected end of JSON input")
	assert.Empty(t, hub.Warnings)

	// and by json we mean an object
	hub, err = testHub(t, nil, "[]")
	cstest.RequireErrorContains(t, err, "invalid hub index: failed to parse index: json: cannot unmarshal array into Go value of type cwhub.HubItems")
	assert.Empty(t, hub.Warnings)
}

func TestIndexUnknownItemType(t *testing.T) {
	// Allow unknown fields in the top level object, likely new item types
	hub, err := testHub(t, nil, `{"goodies": {}}`)
	require.NoError(t, err)
	assert.Empty(t, hub.Warnings)
}

func TestHubUpdate(t *testing.T) {
	ctx := t.Context()
	// update an empty hub with a index containing a parser.
	hub, err := testHub(t, nil, "{}")
	require.NoError(t, err)

	index1 := `
{
  "parsers": {
    "author/pars1": {
      "path": "parsers/s01-parse/pars1.yaml",
      "stage": "s01-parse",
      "version": "0.0",
      "versions": {
        "0.0": {
          "digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        }
      },
      "content": "{}"
    }
  }
}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main/.index.json" {
			w.WriteHeader(http.StatusNotFound)
		}

		_, err = w.Write([]byte(index1))
		assert.NoError(t, err)
	}))
	defer mockServer.Close()

	downloader := &Downloader{
		Branch:      "main",
		URLTemplate: mockServer.URL + "/%s/%s",
	}

	updated, err := hub.Update(ctx, downloader, true)
	require.NoError(t, err)
	assert.True(t, updated)

	err = hub.Load()
	require.NoError(t, err)

	item := hub.GetItem("parsers", "author/pars1")
	assert.NotEmpty(t, item)
	assert.Equal(t, "author/pars1", item.Name)
}

func TestHubUpdateInvalidTemplate(t *testing.T) {
	ctx := t.Context()
	hub, err := testHub(t, nil, "{}")
	require.NoError(t, err)

	downloader := &Downloader{
		Branch:      "main",
		URLTemplate: "x",
	}

	updated, err := hub.Update(ctx, downloader, true)
	cstest.RequireErrorMessage(t, err, "failed to build hub index request: invalid URL template 'x'")
	assert.False(t, updated)
}

func TestHubUpdateCannotWrite(t *testing.T) {
	ctx := t.Context()
	hub, err := testHub(t, nil, "{}")
	require.NoError(t, err)

	index1 := `
{
  "parsers": {
    "author/pars1": {
      "path": "parsers/s01-parse/pars1.yaml",
      "stage": "s01-parse",
      "version": "0.0",
      "versions": {
        "0.0": {
          "digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        }
      },
      "content": "{}"
    }
  }
}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main/.index.json" {
			w.WriteHeader(http.StatusNotFound)
		}

		_, err = w.Write([]byte(index1))
		assert.NoError(t, err)
	}))
	defer mockServer.Close()

	downloader := &Downloader{
		Branch:      "main",
		URLTemplate: mockServer.URL + "/%s/%s",
	}

	hub.local.HubIndexFile = "/proc/foo/bar/baz/.index.json"

	updated, err := hub.Update(ctx, downloader, true)
	cstest.RequireErrorContains(t, err, "failed to create temporary download file for /proc/foo/bar/baz/.index.json")
	assert.False(t, updated)
}

func TestHubUpdateAfterLoad(t *testing.T) {
	ctx := t.Context()
	// Update() can't be called after Load() if the hub is not completely empty.
	index1 := `
{
  "parsers": {
    "author/pars1": {
      "path": "parsers/s01-parse/pars1.yaml",
      "stage": "s01-parse",
      "version": "0.0",
      "versions": {
        "0.0": {
          "digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        }
      },
      "content": "{}"
    }
  }
}`
	hub, err := testHub(t, nil, index1)
	require.NoError(t, err)

	index2 := `
{
  "parsers": {
    "author/pars2": {
      "path": "parsers/s01-parse/pars2.yaml",
      "stage": "s01-parse",
      "version": "0.0",
      "versions": {
        "0.0": {
          "digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        }
      },
      "content": "{}"
    }
  }
}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main/.index.json" {
			w.WriteHeader(http.StatusNotFound)
		}

		_, err = w.Write([]byte(index2))
		assert.NoError(t, err)
	}))
	defer mockServer.Close()

	downloader := &Downloader{
		Branch:      "main",
		URLTemplate: mockServer.URL + "/%s/%s",
	}

	updated, err := hub.Update(ctx, downloader, true)
	require.ErrorIs(t, err, ErrUpdateAfterSync)
	assert.False(t, updated)
}
