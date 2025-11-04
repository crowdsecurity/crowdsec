package journalctlacquisition

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	Filters []string `yaml:"journalctl_filter"`
	since   string // set only by DSN
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	config := Configuration{}

	// defaults
	config.Mode = configuration.TAIL_MODE

	err := yaml.UnmarshalWithOptions(yamlConfig, &config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse journalctl acquisition config: %s", yaml.FormatError(err, false, false))
	}

	if len(config.Filters) == 0 {
		return errors.New("journalctl_filter is required")
	}

	s.config = config
	s.setSrc(s.config.Filters)

	return nil
}

func (s *Source) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	s.setLogger(logger, 0, s.src)

	return nil
}

func (s *Source) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	var (
		filters  []string
		since    string
		logLevel log.Level
	)

	// format for the DSN is : journalctl://filters=FILTER1&filters=FILTER2
	if !strings.HasPrefix(dsn, "journalctl://") {
		return fmt.Errorf("invalid DSN %s for journalctl source, must start with journalctl://", dsn)
	}

	qs := strings.TrimPrefix(dsn, "journalctl://")
	if qs == "" {
		return errors.New("empty journalctl:// DSN")
	}

	params, err := url.ParseQuery(qs)
	if err != nil {
		return fmt.Errorf("could not parse journalctl DSN: %w", err)
	}

	for key, value := range params {
		switch key {
		case "filters":
			filters = append(filters, value...)
		case "log_level":
			if len(value) != 1 {
				return errors.New("expected exactly one value for 'log_level'")
			}

			lvl, err := log.ParseLevel(value[0])
			if err != nil {
				return err
			}

			logLevel = lvl
		case "since":
			if len(value) != 1 {
				return errors.New("expected exactly one value for 'since'")
			}

			since = value[0]
		default:
			return fmt.Errorf("unsupported key %s in journalctl DSN", key)
		}
	}

	s.config = Configuration{
		DataSourceCommonCfg: configuration.DataSourceCommonCfg{
			Mode:     configuration.CAT_MODE,
			Labels:   labels,
			UniqueId: uuid,
		},
		Filters: filters,
		since:   since,
	}

	s.setSrc(s.config.Filters)
	s.setLogger(logger, logLevel, s.src)

	return nil
}
