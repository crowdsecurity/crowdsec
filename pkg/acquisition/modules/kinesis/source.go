package kinesisacquisition

import (
	"github.com/aws/aws-sdk-go-v2/service/kinesis"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel    metrics.AcquisitionMetricsLevel
	Config          Configuration
	logger          *log.Entry
	kClient         *kinesis.Client
	shardReaderTomb *tomb.Tomb
}

func (s *Source) GetUuid() string {
	return s.Config.UniqueId
}

func (s *Source) GetMode() string {
	return s.Config.Mode
}

func (*Source) GetName() string {
	return ModuleName
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) Dump() any {
	return s
}
