package syslogacquisition

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	syslogserver "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/influxdata/go-syslog/v3/rfc3164"
	"github.com/influxdata/go-syslog/v3/rfc5424"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
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

func (s *SyslogSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
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
	if syslogConfig.MaxMessageLen == 0 {
		syslogConfig.MaxMessageLen = 2048
	}
	if !validatePort(syslogConfig.Port) {
		return fmt.Errorf("invalid port %d", syslogConfig.Port)
	}
	if !validateAddr(syslogConfig.Addr) {
		return fmt.Errorf("invalid listen IP %s", syslogConfig.Addr)
	}
	s.config = syslogConfig
	return nil
}

func (s *SyslogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	c := make(chan syslogserver.SyslogMessage)
	s.server = &syslogserver.SyslogServer{Logger: s.logger.WithField("syslog", "internal"), MaxMessageLen: s.config.MaxMessageLen}
	s.server.SetChannel(c)
	err := s.server.Listen(s.config.Addr, s.config.Port)
	if err != nil {
		return errors.Wrap(err, "could not start syslog server")
	}
	s.serverTomb = s.server.StartServer()
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/syslog/live")
		return s.handleSyslogMsg(out, t, c)
	})
	return nil
}

func (s *SyslogSource) buildLogFromSyslog(ts *time.Time, hostname *string,
	appname *string, pid *string, msg *string) (string, error) {
	ret := ""
	if msg == nil {
		return "", errors.Errorf("missing message field in syslog message")
	}
	if ts != nil {
		ret += ts.Format("Jan 2 15:04:05")
	} else {
		s.logger.Tracef("%s - missing TS", *msg)
		ret += time.Now().UTC().Format("Jan 2 15:04:05")
	}
	if hostname != nil {
		ret += " " + *hostname
	} else {
		s.logger.Tracef("%s - missing host", *msg)
		ret += " unknownhost"
	}
	if appname != nil {
		ret += " " + *appname
	} else {
		return "", errors.Errorf("missing appname field in syslog message")
	}
	if pid != nil {
		/*
			!!! ugly hack !!!
			Due to a bug in the syslog parser we use (https://github.com/influxdata/go-syslog/issues/31),
			the ProcID field will contain garbage if the message as a ] anywhere in it.
			Assume that a correctly formated ProcID only contains number, and if this is not the case, set it to an arbitrary value
		*/
		_, err := strconv.Atoi(*pid)
		if err != nil {
			ret += "[1]: "
		} else {
			ret += "[" + *pid + "]: "
		}
	} else {
		ret += ": "
	}
	if msg != nil {
		ret += *msg
	}
	return ret, nil

}

func (s *SyslogSource) handleSyslogMsg(out chan types.Event, t *tomb.Tomb, c chan syslogserver.SyslogMessage) error {
	for {
		select {
		case <-t.Dying():
			s.logger.Info("Syslog datasource is dying")
			s.serverTomb.Kill(nil)
			return s.serverTomb.Wait()
		case <-s.serverTomb.Dying():
			s.logger.Info("Syslog server is dying, exiting")
			return nil
		case <-s.serverTomb.Dead():
			s.logger.Info("Syslog server has exited")
			return nil
		case syslogLine := <-c:
			var line string
			var ts time.Time

			logger := s.logger.WithField("client", syslogLine.Client)
			logger.Tracef("raw: %s", syslogLine)
			linesReceived.With(prometheus.Labels{"source": syslogLine.Client}).Inc()
			p := rfc5424.NewParser()
			m, err := p.Parse(syslogLine.Message)
			if err != nil {
				logger.Debugf("could not parse as RFC5424 (%s)", err)
				p = rfc3164.NewParser(rfc3164.WithYear(rfc3164.CurrentYear{}))
				m, err = p.Parse(syslogLine.Message)
				if err != nil {
					logger.Errorf("could not parse message: %s", err)
					logger.Debugf("could not parse as RFC3164 (%s) : %s", err, syslogLine.Message)
					continue
				}
				msg := m.(*rfc3164.SyslogMessage)
				line, err = s.buildLogFromSyslog(msg.Timestamp, msg.Hostname, msg.Appname, msg.ProcID, msg.Message)
				if err != nil {
					logger.Debugf("could not parse as RFC3164 (%s) : %s", err, syslogLine.Message)
					logger.Error(err)
					continue
				}
				linesParsed.With(prometheus.Labels{"source": syslogLine.Client,
					"type": "RFC3164"}).Inc()
			} else {
				msg := m.(*rfc5424.SyslogMessage)
				line, err = s.buildLogFromSyslog(msg.Timestamp, msg.Hostname, msg.Appname, msg.ProcID, msg.Message)
				if err != nil {
					log.Debugf("could not parse message as RFC5424 (%s) : %s", err, syslogLine.Message)
					logger.Error(err)
					continue
				}
				linesParsed.With(prometheus.Labels{"source": syslogLine.Client,
					"type": "RFC5424"}).Inc()

			}
			l := types.Line{}
			l.Raw = line
			l.Module = s.GetName()
			l.Labels = s.config.Labels
			l.Time = ts
			l.Src = syslogLine.Client
			l.Process = true
			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		}
	}
}
