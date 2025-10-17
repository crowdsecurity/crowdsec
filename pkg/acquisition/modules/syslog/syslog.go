package syslogacquisition

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/rfc3164"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/rfc5424"
	syslogserver "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/server"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type SyslogConfiguration struct {
	Proto                             string `yaml:"protocol,omitempty"`
	Port                              int    `yaml:"listen_port,omitempty"`
	Addr                              string `yaml:"listen_addr,omitempty"`
	MaxMessageLen                     int    `yaml:"max_message_len,omitempty"`
	DisableRFCParser                  bool   `yaml:"disable_rfc_parser,omitempty"` // if true, we don't try to be smart and just remove the PRI
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type SyslogSource struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	config       SyslogConfiguration
	logger       *log.Entry
	server       *syslogserver.SyslogServer
	serverTomb   *tomb.Tomb
}

func (s *SyslogSource) GetUuid() string {
	return s.config.UniqueId
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
	return []prometheus.Collector{metrics.SyslogDataSourceLinesReceived, metrics.SyslogDataSourceLinesParsed}
}

func (s *SyslogSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.SyslogDataSourceLinesReceived, metrics.SyslogDataSourceLinesParsed}
}

func validatePort(port int) bool {
	return port > 0 && port <= 65535
}

func validateAddr(addr string) bool {
	return net.ParseIP(addr) != nil
}

func (s *SyslogSource) UnmarshalConfig(yamlConfig []byte) error {
	s.config = SyslogConfiguration{}
	s.config.Mode = configuration.TAIL_MODE

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse syslog configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.config.Addr == "" {
		s.config.Addr = "127.0.0.1" // do we want a usable or secure default ?
	}
	if s.config.Port == 0 {
		s.config.Port = 514
	}
	if s.config.MaxMessageLen == 0 {
		s.config.MaxMessageLen = 2048
	}
	if !validatePort(s.config.Port) {
		return fmt.Errorf("invalid port %d", s.config.Port)
	}
	if !validateAddr(s.config.Addr) {
		return fmt.Errorf("invalid listen IP %s", s.config.Addr)
	}

	return nil
}

func (s *SyslogSource) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.logger.Infof("Starting syslog datasource configuration")
	s.metricsLevel = metricsLevel
	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
}

func (s *SyslogSource) StreamingAcquisition(_ context.Context, out chan types.Event, t *tomb.Tomb) error {
	c := make(chan syslogserver.SyslogMessage)
	s.server = &syslogserver.SyslogServer{Logger: s.logger.WithField("syslog", "internal"), MaxMessageLen: s.config.MaxMessageLen}
	s.server.SetChannel(c)
	err := s.server.Listen(s.config.Addr, s.config.Port)
	if err != nil {
		return fmt.Errorf("could not start syslog server: %w", err)
	}
	s.serverTomb = s.server.StartServer()
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/syslog/live")
		return s.handleSyslogMsg(out, t, c)
	})
	return nil
}

func (s *SyslogSource) buildLogFromSyslog(ts time.Time, hostname string,
	appname string, pid string, msg string,
) string {
	ret := ""
	if !ts.IsZero() {
		ret += ts.Format("Jan 2 15:04:05")
	} else {
		s.logger.Tracef("%s - missing TS", msg)
		ret += time.Now().UTC().Format("Jan 2 15:04:05")
	}
	if hostname != "" {
		ret += " " + hostname
	} else {
		s.logger.Tracef("%s - missing host", msg)
		ret += " unknownhost"
	}
	if appname != "" {
		ret += " " + appname
	}
	if pid != "" {
		ret += "[" + pid + "]: "
	} else {
		ret += ": "
	}
	if msg != "" {
		ret += msg
	}
	return ret
}

func (s *SyslogSource) parseLine(syslogLine syslogserver.SyslogMessage) string {
	var line string

	logger := s.logger.WithField("client", syslogLine.Client)
	logger.Tracef("raw: %s", syslogLine)
	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.SyslogDataSourceLinesReceived.With(prometheus.Labels{"source": syslogLine.Client, "datasource_type": "syslog", "acquis_type": s.config.Labels["type"]}).Inc()
	}
	if !s.config.DisableRFCParser {
		p := rfc3164.NewRFC3164Parser(rfc3164.WithCurrentYear())
		err := p.Parse(syslogLine.Message)
		if err != nil {
			logger.Debugf("could not parse as RFC3164 (%s)", err)
			p2 := rfc5424.NewRFC5424Parser()
			err = p2.Parse(syslogLine.Message)
			if err != nil {
				logger.Errorf("could not parse message: %s", err)
				logger.Debugf("could not parse as RFC5424 (%s) : %s", err, syslogLine.Message)
				return ""
			}
			line = s.buildLogFromSyslog(p2.Timestamp, p2.Hostname, p2.Tag, p2.PID, p2.Message)
			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.SyslogDataSourceLinesParsed.With(prometheus.Labels{"source": syslogLine.Client, "type": "rfc5424", "datasource_type": "syslog", "acquis_type": s.config.Labels["type"]}).Inc()
			}
		} else {
			line = s.buildLogFromSyslog(p.Timestamp, p.Hostname, p.Tag, p.PID, p.Message)
			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.SyslogDataSourceLinesParsed.With(prometheus.Labels{"source": syslogLine.Client, "type": "rfc3164", "datasource_type": "syslog", "acquis_type": s.config.Labels["type"]}).Inc()
			}
		}
	} else {
		if len(syslogLine.Message) < 3 {
			logger.Errorf("malformated message, missing PRI (message too short)")
			return ""
		}
		if syslogLine.Message[0] != '<' {
			logger.Errorf("malformated message, missing PRI beginning")
			return ""
		}
		priEnd := bytes.Index(syslogLine.Message, []byte(">"))
		if priEnd == -1 {
			logger.Errorf("malformated message, missing PRI end")
			return ""
		}
		if priEnd > 4 {
			logger.Errorf("malformated message, PRI too long")
			return ""
		}
		for i := 1; i < priEnd; i++ {
			if syslogLine.Message[i] < '0' || syslogLine.Message[i] > '9' {
				logger.Errorf("malformated message, PRI not a number")
				return ""
			}
		}
		line = string(syslogLine.Message[priEnd+1:])
	}

	return strings.TrimSuffix(line, "\n")
}

func (s *SyslogSource) handleSyslogMsg(out chan types.Event, t *tomb.Tomb, c chan syslogserver.SyslogMessage) error {
	killed := false
	for {
		select {
		case <-t.Dying():
			if !killed {
				s.logger.Info("Syslog datasource is dying")
				s.serverTomb.Kill(nil)
				killed = true
			}
		case <-s.serverTomb.Dead():
			s.logger.Info("Syslog server has exited")
			return nil
		case syslogLine := <-c:
			line := s.parseLine(syslogLine)
			if line == "" {
				continue
			}

			var ts time.Time

			l := types.Line{}
			l.Raw = line
			l.Module = s.GetName()
			l.Labels = s.config.Labels
			l.Time = ts
			l.Src = syslogLine.Client
			l.Process = true
			evt := types.MakeEvent(s.config.UseTimeMachine, types.LOG, true)
			evt.Line = l
			out <- evt
		}
	}
}
