package kafkaacquisition

import (
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       Configuration
	logger       *logrus.Entry
	Reader       *kafka.Reader
}

func (s *Source) GetUuid() string {
	return s.Config.UniqueId
}

func (s *Source) GetMode() string {
	return s.Config.Mode
}

func (*Source) GetName() string {
	return "kafka"
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) Dump() any {
	return s
}
