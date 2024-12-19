package cwhub

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestInitHubUpdate(t *testing.T) {
	hub := envSetup(t)
	remote := &RemoteHubCfg{
		URLTemplate: mockURLTemplate,
		Branch:      "master",
		IndexPath:   ".index.json",
	}

	_, err := NewHub(hub.local, remote, nil)
	require.NoError(t, err)

	ctx := context.Background()

	err = hub.Update(ctx, false)
	require.NoError(t, err)

	err = hub.Load()
	require.NoError(t, err)
}

func TestUpdateIndex(t *testing.T) {
	// bad url template
	fmt.Println("Test 'bad URL'")

	tmpIndex, err := os.CreateTemp("", "index.json")
	require.NoError(t, err)

	// close the file to avoid preventing the rename on windows
	err = tmpIndex.Close()
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(tmpIndex.Name())
	})

	hub := envSetup(t)

	hub.remote = &RemoteHubCfg{
		URLTemplate: "x",
		Branch:      "",
		IndexPath:   "",
	}

	hub.local.HubIndexFile = tmpIndex.Name()

	ctx := context.Background()

	err = hub.Update(ctx, false)
	cstest.RequireErrorContains(t, err, "failed to build hub index request: invalid URL template 'x'")

	// bad domain
	fmt.Println("Test 'bad domain'")

	hub.remote = &RemoteHubCfg{
		URLTemplate: "https://baddomain/crowdsecurity/%s/%s",
		Branch:      "master",
		IndexPath:   ".index.json",
	}

	err = hub.Update(ctx, false)
	require.NoError(t, err)
	// XXX: this is not failing
	//	cstest.RequireErrorContains(t, err, "failed http request for hub index: Get")

	// bad target path
	fmt.Println("Test 'bad target path'")

	hub.remote = &RemoteHubCfg{
		URLTemplate: mockURLTemplate,
		Branch:      "master",
		IndexPath:   ".index.json",
	}

	hub.local.HubIndexFile = "/does/not/exist/index.json"

	err = hub.Update(ctx, false)
	cstest.RequireErrorContains(t, err, "failed to create temporary download file for /does/not/exist/index.json:")
}
