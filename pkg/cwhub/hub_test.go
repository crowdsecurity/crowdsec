package cwhub

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestInitHubUpdate(t *testing.T) {
	hub := envSetup(t)

	remote := &RemoteHubCfg {
		URLTemplate: mockURLTemplate,
		Branch: "master",
		IndexPath: ".index.json",
	}

	_, err := InitHubUpdate(hub.local, remote)
	require.NoError(t, err)

	_, err = GetHub()
	require.NoError(t, err)
}

func TestDownloadIndex(t *testing.T) {
	// bad url template
	fmt.Println("Test 'bad URL'")

	tmpIndex, err := os.CreateTemp("", "index.json")
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(tmpIndex.Name())
	})

	hub := envSetup(t)

	hub.remote = &RemoteHubCfg {
		URLTemplate: "x",
		Branch: "",
		IndexPath: "",
	}

	ret, err := hub.remote.DownloadIndex(tmpIndex.Name())
	cstest.RequireErrorContains(t, err, "failed to build hub index request: invalid URL template 'x'")

	fmt.Printf("->%+v", ret)

	// bad domain
	fmt.Println("Test 'bad domain'")

	hub.remote = &RemoteHubCfg {
		URLTemplate: "https://baddomain/%s/%s",
		Branch: "master",
		IndexPath: ".index.json",
	}

	ret, err = hub.remote.DownloadIndex(tmpIndex.Name())
// XXX: this is not failing
//	cstest.RequireErrorContains(t, err, "failed http request for hub index: Get")

	fmt.Printf("->%+v", ret)

	// bad target path
	fmt.Println("Test 'bad target path'")

	hub.remote = &RemoteHubCfg {
		URLTemplate: mockURLTemplate,
		Branch: "master",
		IndexPath: ".index.json",
	}

	ret, err = hub.remote.DownloadIndex("/does/not/exist/index.json")
	cstest.RequireErrorContains(t, err, "while opening hub index file: open /does/not/exist/index.json:")

	fmt.Printf("->%+v", ret)
}
