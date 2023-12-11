package syslogacquisition

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/rfc3164"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/rfc5424"
	syslogserver "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/server"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type SyslogConfiguration struct {
	Proto                             string `yaml:"protocol,omitempty"`
	Port                              int    `yaml:"listen_port,omitempty"`
	Addr                              string `yaml:"listen_addr,omitempty"`
	MaxMessageLen                     int    `yaml:"max_message_len,omitempty"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type SyslogSource struct {
	config     SyslogConfiguration
	logger     *log.Entry
	server     *syslogserver.SyslogServer
	serverTomb *tomb.Tomb
}

var linesReceived = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_syslogsource_hits_total",
		Help: "Total lines that were received.",
	},
	[]string{"source"})

var linesParsed = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_syslogsource_parsed_total",
		Help: "Total lines that were successfully parsed",
	},
	[]string{"source", "type"})

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
	return []prometheus.Collector{linesReceived, linesParsed}
}

func (s *SyslogSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesReceived, linesParsed}
}

func (s *SyslogSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
}

func (s *SyslogSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
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

	err := yaml.UnmarshalStrict(yamlConfig, &s.config)
	if err != nil {
		return fmt.Errorf("cannot parse syslog configuration: %w", err)
	}

	if s.config.Addr == "" {
		s.config.Addr = "127.0.0.1" //do we want a usable or secure default ?
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

func (s *SyslogSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	s.logger = logger
	s.logger.Infof("Starting syslog datasource configuration")

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
}

func (s *SyslogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
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
	appname string, pid string, msg string) string {
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
			var line string
			var ts time.Time

			logger := s.logger.WithField("client", syslogLine.Client)
			logger.Tracef("raw: %s", syslogLine)
			linesReceived.With(prometheus.Labels{"source": syslogLine.Client}).Inc()
			p := rfc3164.NewRFC3164Parser(rfc3164.WithCurrentYear())
			err := p.Parse(syslogLine.Message)
			if err != nil {
				logger.Debugf("could not parse as RFC3164 (%s)", err)
				p2 := rfc5424.NewRFC5424Parser()
				err = p2.Parse(syslogLine.Message)
				if err != nil {
					logger.Errorf("could not parse message: %s", err)
					logger.Debugf("could not parse as RFC5424 (%s) : %s", err, syslogLine.Message)
					continue
				}
				line = s.buildLogFromSyslog(p2.Timestamp, p2.Hostname, p2.Tag, p2.PID, p2.Message)
				linesParsed.With(prometheus.Labels{"source": syslogLine.Client, "type": "rfc5424"}).Inc()
			} else {
				line = s.buildLogFromSyslog(p.Timestamp, p.Hostname, p.Tag, p.PID, p.Message)
				linesParsed.With(prometheus.Labels{"source": syslogLine.Client, "type": "rfc3164"}).Inc()
			}

			line = strings.TrimSuffix(line, "\n")

			l := types.Line{}
			l.Raw = line
			l.Module = s.GetName()
			l.Labels = s.config.Labels
			l.Time = ts
			l.Src = syslogLine.Client
			l.Process = true
			if !s.config.UseTimeMachine {
				out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
			} else {
				out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
			}
		}
	}
}
