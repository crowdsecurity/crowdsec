package cwhub

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	log "github.com/sirupsen/logrus"
)

func TestDownloadHubIdx(t *testing.T) {
	back := RawFileURLTemplate
	//bad url template
	RawFileURLTemplate = "x"
	ret, err := DownloadHubIdx(&csconfig.Hub{})
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "failed to build request for hub index: parse ") {
		log.Errorf("unexpected error %s", err)
	}
	//bad domain
	RawFileURLTemplate = "https://baddomain/crowdsecurity/hub/%s/%s"
	ret, err = DownloadHubIdx(&csconfig.Hub{})
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "failed http request for hub index: Get") {
		log.Errorf("unexpected error %s", err)
	}

	//bad target path
	RawFileURLTemplate = back
	ret, err = DownloadHubIdx(&csconfig.Hub{HubIndexFile: "/does/not/exist/index.json"})
	if err == nil || !strings.HasPrefix(fmt.Sprintf("%s", err), "while opening hub index file: open /does/not/exist/index.json:") {
		log.Errorf("unexpected error %s", err)
	}

	RawFileURLTemplate = back
	fmt.Printf("->%+v", ret)
}
