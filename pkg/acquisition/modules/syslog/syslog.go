package syslog

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	syslogserver "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type SyslogConfiguration struct {
	Proto string `yaml:"protocol,omitempty"`
	Port  int    `yaml:"port,omitempty"`
	Addr  string `yaml:"addr,omitempty"`
	//TODO: Add TLS support
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type SyslogSource struct {
	config SyslogConfiguration
	logger *log.Entry
	server *syslogserver.SyslogServer
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
	s.config = syslogConfig
	return nil
}

func (s *SyslogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	//channel := make(syslog.LogPartsChannel)
	//handler := syslog.NewChannelHandler(channel)

	s.server = &syslogserver.SyslogServer{}
	err := s.server.SetProtocol(s.config.Proto)
	if err != nil {
		return errors.Wrap(err, "could not set syslog server protocol")
	}
	//s.server.SetHandler(handler)
	//err := s.server.ListenUDP(fmt.Sprintf("%s:%d", s.config.Addr, s.config.Port))
	/*if err != nil {
		return errors.Wrap(err, "could not listen")
	}
	err = s.server.Boot()
	if err != nil {
		return errors.Wrap(err, "could not start syslog server")
	}
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/syslog/live")
		return s.handleSyslogMsg(out, t, channel)
	})*/
	return nil
}

func (s *SyslogSource) handleSyslogMsg(out chan types.Event, t *tomb.Tomb) error {
	for {
		select {
		case <-t.Dying():
			s.logger.Info("Syslog datasource is dying")
			/*case logParts := <-channel:
			var line string
			spew.Dump(logParts)
			//rebuild the syslog line from the part
			//TODO: handle the RFC format and cases such as missing PID, or PID embedded in the app_name
			if logParts["content"] == nil {
				line = fmt.Sprintf("%s %s %s[%s]: %s", logParts["timestamp"], logParts["hostname"],
					logParts["app_name"], logParts["proc_id"], logParts["message"])
			} else {
				line = fmt.Sprintf("%s %s %s: %s", logParts["timestamp"],
					logParts["hostname"], logParts["tag"], logParts["content"])
			}
			l := types.Line{}
			l.Raw = line
			l.Labels = s.config.Labels
			//l.Time = logParts["timestamp"].(string)
			l.Src = logParts["client"].(string)
			l.Process = true
			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}*/
		}
	}
}
