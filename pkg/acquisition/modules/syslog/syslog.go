package syslog

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"gopkg.in/mcuadros/go-syslog.v2"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type SyslogConfiguration struct {
	Proto        string `yaml:"protocol,omitempty"`
	Port         int    `yaml:"port,omitempty"`
	Addr         string `yaml:"addr,omitempty"`
	syslogFormat string
	//TODO: Add TLS support
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type SyslogSource struct {
	config SyslogConfiguration
	logger *log.Entry
}

func (s *SyslogSource) GetName() string {
	return "syslog"
}

func (s *SyslogSource) GetMode() string {
	return s.config.Mode
}

func (s *SyslogSource) Dump() interface{} {
	return s
}

func (s *SyslogSource) CanRun() error {
	return nil
}

func (s *SyslogSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (s *SyslogSource) ConfigureByDSN(dsn string, labelType string, logger *log.Entry) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
}

func (s *SyslogSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
}

func (s *SyslogSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	s.logger = logger
	s.logger.Infof("Starting syslog datasource configuration")
	syslogConfig := SyslogConfiguration{}
	syslogConfig.Mode = configuration.TAIL_MODE
	err := yaml.UnmarshalStrict(yamlConfig, &syslogConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse syslog configuration")
	}
	if syslogConfig.Addr == "" {
		syslogConfig.Addr = "127.0.0.1" //do we want a usable or secure default ?
	}
	if syslogConfig.Port == 0 {
		syslogConfig.Port = 514
	}
	if syslogConfig.Proto == "" {
		syslogConfig.Proto = "udp"
	}
	/*if syslogConfig.syslogFormat == "" {
		syslogConfig.syslogFormat = syslog.RFC3164
	}*/
	s.config = syslogConfig
	return nil
}

func (s *SyslogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	err := server.ListenUDP(fmt.Sprintf("%s:%d", s.config.Addr, s.config.Port))
	if err != nil {
		return errors.Wrap(err, "could not listen")
	}
	err = server.Boot()
	if err != nil {
		return errors.Wrap(err, "could not start syslog server")
	}
	t.Go(
		func() error {
			for logParts := range channel {
				spew.Dump(logParts)
			}
			return nil
		})
	return nil
}
