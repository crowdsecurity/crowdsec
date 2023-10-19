package cwhub

import (
	"fmt"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestDownloadHubIdx(t *testing.T) {
	back := RawFileURLTemplate
	// bad url template
	fmt.Println("Test 'bad URL'")

	tmpIndex, err := os.CreateTemp("", "index.json")
	if err != nil {
		t.Fatalf("failed to create temp file : %s", err)
	}

	t.Cleanup(func() {
		os.Remove(tmpIndex.Name())
	})

	RawFileURLTemplate = "x"

	ret, err := DownloadHubIdx(tmpIndex.Name())
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "failed to build request for hub index: parse ") {
		log.Errorf("unexpected error %s", err)
	}

	fmt.Printf("->%+v", ret)

	// bad domain
	fmt.Println("Test 'bad domain'")

	RawFileURLTemplate = "https://baddomain/%s/%s"

	ret, err = DownloadHubIdx(tmpIndex.Name())
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "failed http request for hub index: Get") {
		log.Errorf("unexpected error %s", err)
	}

	fmt.Printf("->%+v", ret)

	// bad target path
	fmt.Println("Test 'bad target path'")

	RawFileURLTemplate = back

	ret, err = DownloadHubIdx("/does/not/exist/index.json")
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "while opening hub index file: open /does/not/exist/index.json:") {
		log.Errorf("unexpected error %s", err)
	}

	RawFileURLTemplate = back

	fmt.Printf("->%+v", ret)
}
