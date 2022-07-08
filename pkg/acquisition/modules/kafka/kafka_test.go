package kafkacquisition

import (
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
)

func TestConfigure(t *testing.T) {
	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config: `
foobar: bla
source: kafka`,
			expectedErr: "line 2: field foobar not found in type kafkacquisition.KafkaConfiguration",
		},
		{
			config:      `source: kafka`,
			expectedErr: "cannot create a kafka reader with an empty list of broker addresses",
		},
		{
			config: `
source: kafka
brokers:
  - bla
timeout: 5`,
			expectedErr: "cannot create a kafka reader with am empty topic",
		},
		{
			config: `
source: kafka
brokers:
  - bla
topic: toto
timeout: aa`,
			expectedErr: "cannot create kafka dialer: strconv.Atoi: parsing \"aa\": invalid syntax",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "kafka",
	})
	for _, test := range tests {
		k := KafkaSource{}
		err := k.Configure([]byte(test.config), subLogger)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}
