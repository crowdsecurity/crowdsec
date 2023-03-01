package s3acquisition

import (
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type S3Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	AwsProfile                        *string `yaml:"aws_profile"`
	AwsRegion                         string  `yaml:"aws_region"`
	AwsEndpoint                       string  `yaml:"aws_endpoint"`
	BucketName                        string  `yaml:"bucket_name"`
	Prefix                            string  `yaml:"prefix"`
	PollingMethod                     string  `yaml:"polling_method"`
	PollingInterval                   int     `yaml:"polling_interval"`
}

type S3Source struct {
	Config          S3Configuration
	logger          *log.Entry
	s3Client        *s3.S3
	shardReaderTomb *tomb.Tomb
}

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_s3_hits_total",
		Help: "Number of events read per bucket.",
	},
	[]string{"bucket"},
)

func (s *S3Source) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}
func (s *S3Source) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (s *S3Source) UnmarshalConfig([]byte) error {
	return nil
}

func (s *S3Source) Configure([]byte, *log.Entry) error {
	return nil
}

func (s *S3Source) ConfigureByDSN(string, map[string]string, *log.Entry) error {
	return nil
}

func (s *S3Source) GetMode() string {
	return s.Config.Mode
}

func (s *S3Source) GetName() string {
	return "s3"
}

func (s *S3Source) OneShotAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (s *S3Source) StreamingAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (s *S3Source) CanRun() error {
	return nil
}

func (s *S3Source) Dump() interface{} {
	return s
}
