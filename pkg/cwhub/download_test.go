package cwhub

import (
	"fmt"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func TestDownloadHubIdx(t *testing.T) {
	back := RawFileURLTemplate
	// bad url template
	fmt.Println("Test 'bad URL'")

	RawFileURLTemplate = "x"

	ret, err := DownloadHubIdx(&csconfig.Hub{})
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "failed to build request for hub index: parse ") {
		log.Errorf("unexpected error %s", err)
	}

	fmt.Printf("->%+v", ret)

	// bad domain
	fmt.Println("Test 'bad domain'")

	RawFileURLTemplate = "https://baddomain/%s/%s"

	ret, err = DownloadHubIdx(&csconfig.Hub{})
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "failed http request for hub index: Get") {
		log.Errorf("unexpected error %s", err)
	}

	fmt.Printf("->%+v", ret)

	// bad target path
	fmt.Println("Test 'bad target path'")

	RawFileURLTemplate = back

	ret, err = DownloadHubIdx(&csconfig.Hub{HubIndexFile: "/does/not/exist/index.json"})
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "while opening hub index file: open /does/not/exist/index.json:") {
		log.Errorf("unexpected error %s", err)
	}

	RawFileURLTemplate = back

	fmt.Printf("->%+v", ret)
}
