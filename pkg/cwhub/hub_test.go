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

	_, err := InitHubUpdate(hub.cfg)
	require.NoError(t, err)

	_, err = GetHub()
	require.NoError(t, err)
}

func TestDownloadIndex(t *testing.T) {
	back := RawFileURLTemplate
	// bad url template
	fmt.Println("Test 'bad URL'")

	tmpIndex, err := os.CreateTemp("", "index.json")
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(tmpIndex.Name())
	})

	RawFileURLTemplate = "x"

	ret, err := DownloadIndex(tmpIndex.Name())
	cstest.RequireErrorContains(t, err, "failed to build request for hub index: parse ")

	fmt.Printf("->%+v", ret)

	// bad domain
	fmt.Println("Test 'bad domain'")

	RawFileURLTemplate = "https://baddomain/%s/%s"

	ret, err = DownloadIndex(tmpIndex.Name())
	cstest.RequireErrorContains(t, err, "failed http request for hub index: Get")

	fmt.Printf("->%+v", ret)

	// bad target path
	fmt.Println("Test 'bad target path'")

	RawFileURLTemplate = back

	ret, err = DownloadIndex("/does/not/exist/index.json")
	cstest.RequireErrorContains(t, err, "while opening hub index file: open /does/not/exist/index.json:")

	RawFileURLTemplate = back

	fmt.Printf("->%+v", ret)
}
