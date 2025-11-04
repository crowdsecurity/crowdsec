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
	since   string // set by DSN
}

func (j *JournalCtlSource) UnmarshalConfig(yamlConfig []byte) error {
	j.config = Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &j.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse journalctl acquisition config: %s", yaml.FormatError(err, false, false))
	}

	if j.config.Mode == "" {
		j.config.Mode = configuration.TAIL_MODE
	}

	if len(j.config.Filters) == 0 {
		return errors.New("journalctl_filter is required")
	}

	j.src = "journalctl-" + strings.Join(j.config.Filters, ".")

	return nil
}

func (j *JournalCtlSource) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	j.logger = logger
	j.metricsLevel = metricsLevel

	err := j.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
}

func (j *JournalCtlSource) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	j.logger = logger

	var (
		filters []string
		since string
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
				return errors.New("expected zero or one value for 'log_level'")
			}

			lvl, err := log.ParseLevel(value[0])
			if err != nil {
				return fmt.Errorf("unknown level %s: %w", value[0], err)
			}

			j.logger.Logger.SetLevel(lvl)
		case "since":
			if since != "" {
				return errors.New("multiple values for 'since'")
			}
			since = value[0]
		default:
			return fmt.Errorf("unsupported key %s in journalctl DSN", key)
		}
	}

	j.config = Configuration{
		DataSourceCommonCfg: configuration.DataSourceCommonCfg{
			Mode:     configuration.CAT_MODE,
			Labels:   labels,
			UniqueId: uuid,
		},
		Filters: filters,
		since:   since,
	}

	return nil
}
