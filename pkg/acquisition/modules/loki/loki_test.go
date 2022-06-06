package loki

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	log "github.com/sirupsen/logrus"
)

func TestConfiguration(t *testing.T) {

	log.Infof("Test 'TestConfigure'")

	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config:      `foobar: asd`,
			expectedErr: "line 1: field foobar not found in type loki.LokiConfiguration",
		},
		{
			config: `
mode: tail
source: loki`,
			expectedErr: "Cannot build Loki url",
		},
		{
			config: `
mode: tail
source: loki
url: stuff://localhost:3100
`,
			expectedErr: "unknown scheme : stuff",
		},
		{
			config: `
mode: tail
source: loki
url: http://localhost:3100/
`,
			expectedErr: "",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "loki",
	})
	for _, test := range tests {
		f := LokiSource{}
		err := f.Configure([]byte(test.config), subLogger)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}
