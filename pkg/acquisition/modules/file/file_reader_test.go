package file_acquisition

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var c = `
filename: /tmp/test_log/*.log
mode: tail
`

func TestPouet(t *testing.T) {
	clog := log.New()
	f := FileSource{}
	f.Configure([]byte(c), clog.WithFields(log.Fields{}))

	out := make(chan types.Event)

	a := tomb.Tomb{}
	f.LiveAcquisition(out, &a)
	a.Wait()
}
