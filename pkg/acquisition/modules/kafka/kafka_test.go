package kafkaacquisition

import (
	"context"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/types"
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
			expectedErr: "line 2: field foobar not found in type kafkaacquisition.KafkaConfiguration",
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
		{
			config: `
source: kafka
brokers:
  - localhost:9092
topic: crowdsec`,
			expectedErr: "",
		},
		{
			config: `
source: kafka
brokers:
  - localhost:9092
topic: crowdsec
partition: 1
group_id: crowdsec`,
			expectedErr: "cannote create kafka reader: cannot specify both group_id and partition",
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

func writeToKafka(w *kafka.Writer, logs []string) {

	for idx, log := range logs {
		err := w.WriteMessages(context.Background(), kafka.Message{
			Key: []byte(strconv.Itoa(idx)),
			// create an arbitrary message payload for the value
			Value: []byte(log),
		})
		if err != nil {
			panic("could not write message " + err.Error())
		}
	}
}

func createTopic(topic string, broker string) {
	conn, err := kafka.Dial("tcp", broker)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		panic(err)
	}
	var controllerConn *kafka.Conn
	controllerConn, err = kafka.Dial("tcp", net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port)))
	if err != nil {
		panic(err)
	}
	defer controllerConn.Close()

	topicConfigs := []kafka.TopicConfig{
		{
			Topic:             topic,
			NumPartitions:     1,
			ReplicationFactor: 1,
		},
	}

	err = controllerConn.CreateTopics(topicConfigs...)
	if err != nil {
		panic(err)
	}
}

func TestStreamingAcquisition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	tests := []struct {
		name          string
		logs          []string
		expectedLines int
		expectedErr   string
	}{
		{
			name: "valid msgs",
			logs: []string{
				"message 1",
				"message 2",
				"message 3",
			},
			expectedLines: 3,
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "kafka",
	})

	createTopic("crowdsecplaintext", "localhost:9092")

	w := kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "crowdsecplaintext",
	})
	if w == nil {
		log.Fatalf("Unable to setup a kafka producer")
	}

	for _, ts := range tests {
		ts := ts
		t.Run(ts.name, func(t *testing.T) {
			k := KafkaSource{}
			err := k.Configure([]byte(`
source: kafka
brokers:
  - localhost:9092
topic: crowdsecplaintext`), subLogger)
			if err != nil {
				t.Fatalf("could not configure kafka source : %s", err)
			}
			tomb := tomb.Tomb{}
			out := make(chan types.Event)
			err = k.StreamingAcquisition(out, &tomb)
			cstest.AssertErrorContains(t, err, ts.expectedErr)

			actualLines := 0
			go writeToKafka(w, ts.logs)
		READLOOP:
			for {
				select {
				case <-out:
					actualLines++
				case <-time.After(2 * time.Second):
					break READLOOP
				}
			}
			require.Equal(t, ts.expectedLines, actualLines)
			tomb.Kill(nil)
			tomb.Wait()
		})
	}

}

func TestStreamingAcquisitionWithSSL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	tests := []struct {
		name          string
		logs          []string
		expectedLines int
		expectedErr   string
	}{
		{
			name: "valid msgs",
			logs: []string{
				"message 1",
				"message 2",
			},
			expectedLines: 2,
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "kafka",
	})

	createTopic("crowdsecssl", "localhost:9092")

	w2 := kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "crowdsecssl",
	})
	if w2 == nil {
		log.Fatalf("Unable to setup a kafka producer")
	}

	for _, ts := range tests {
		ts := ts
		t.Run(ts.name, func(t *testing.T) {
			k := KafkaSource{}
			err := k.Configure([]byte(`
source: kafka
brokers:
  - localhost:9093
topic: crowdsecssl
tls:
  insecure_skip_verify: true
  client_cert: ./testdata/kafkaClient.certificate.pem
  client_key: ./testdata/kafkaClient.key
  ca_cert: ./testdata/snakeoil-ca-1.crt
  `), subLogger)
			if err != nil {
				t.Fatalf("could not configure kafka source : %s", err)
			}
			tomb := tomb.Tomb{}
			out := make(chan types.Event)
			err = k.StreamingAcquisition(out, &tomb)
			cstest.AssertErrorContains(t, err, ts.expectedErr)

			actualLines := 0
			go writeToKafka(w2, ts.logs)
		READLOOP:
			for {
				select {
				case <-out:
					actualLines++
				case <-time.After(2 * time.Second):
					break READLOOP
				}
			}
			require.Equal(t, ts.expectedLines, actualLines)
			tomb.Kill(nil)
			tomb.Wait()
		})
	}

}
