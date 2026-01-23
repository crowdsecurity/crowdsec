package syslogacquisition

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/rfc3164"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/rfc5424"
	syslogserver "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/server"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	srv := &syslogserver.SyslogServer{
		Logger:        s.logger.WithField("syslog", "internal"),
		MaxMessageLen: s.config.MaxMessageLen,
	}

	msgChan := make(chan syslogserver.SyslogMessage)

	if err := srv.Listen(s.config.Addr, s.config.Port); err != nil {
		return fmt.Errorf("could not start syslog server: %w", err)
	}

	defer func() {
		_ = srv.KillServer()
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(msgChan)
		return srv.Serve(ctx, msgChan)
	})

	g.Go(func() error {
		defer close(out)

		for {
			select {
			case <-ctx.Done():
				s.logger.Debug("context canceled")
				return nil

			case msg, ok := <-msgChan:
				if !ok {
					s.logger.Debug("channel closed")
					return nil
				}

				evt, err := s.msgToEvent(msg)
				if err != nil {
					s.logger.Error(err)

					var parseError *ParseError
					if errors.As(err, &parseError) {
						s.logger.WithFields(parseError.Fields()).Debug("syslog parse failed")
					}

					continue
				}

				// s.logger.WithFields(logrus.Fields{"line": evt.Line.Raw, "client": msg.Client}).Debug("sending line")
				out <- *evt
			}
		}
	})

	return g.Wait()
}

func (s *Source) msgToEvent(msg syslogserver.SyslogMessage) (*pipeline.Event, error) {
	line, err := s.parseLine(msg)
	if err != nil {
		return nil, err
	}

	evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
	evt.Line = pipeline.Line{
		Raw:     line,
		Src:     msg.Client,
		Time:    time.Time{},
		Labels:  s.config.Labels,
		Module:  s.GetName(),
		Process: true,
	}

	return &evt, nil
}

func (s *Source) buildLogFromSyslog(ts time.Time, hostname string,
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

var ErrUnrecognized = errors.New("unrecognized syslog message")

type ParseError struct {
	Reason     error
	RawMessage []byte
	// keep the both attempts for ErrUnrecognized
	RFC3164 error
	RFC5424 error
}

func (e *ParseError) Error() string {
	return e.Reason.Error()
}

func (e *ParseError) Unwrap() error {
	return e.Reason
}

func (e *ParseError) Fields() logrus.Fields {
	fields := logrus.Fields{
		"raw": string(e.RawMessage),
	}

	if e.RFC3164 != nil {
		fields["rfc3164_err"] = e.RFC3164.Error()
	}

	if e.RFC5424 != nil {
		fields["rfc5424_err"] = e.RFC5424.Error()
	}

	return fields
}

func stripPRI(msg []byte) (rest []byte, err error) {
	if len(msg) < 3 {
		return nil, &ParseError{Reason: errors.New("message too short"), RawMessage: msg}
	}

	if msg[0] != '<' {
		return nil, &ParseError{Reason: errors.New("missing PRI beginning"), RawMessage: msg}
	}

	end := bytes.Index(msg, []byte(">"))
	if end == -1 {
		return nil, &ParseError{Reason: errors.New("missing PRI end"), RawMessage: msg}
	}

	if end > 4 {
		return nil, &ParseError{Reason: errors.New("PRI too long"), RawMessage: msg}
	}

	for i := 1; i < end; i++ {
		if msg[i] < '0' || msg[i] > '9' {
			return nil, &ParseError{Reason: errors.New("PRI not a number"), RawMessage: msg}
		}
	}

	return msg[end+1:], nil
}

func (s *Source) parseLine(syslogLine syslogserver.SyslogMessage) (string, error) {
	var line string

	logger := s.logger.WithField("client", syslogLine.Client)
	logger.Tracef("raw: %s", syslogLine)

	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.SyslogDataSourceLinesReceived.With(prometheus.Labels{"source": syslogLine.Client, "datasource_type": ModuleName, "acquis_type": s.config.Labels["type"]}).Inc()
	}

	if s.config.DisableRFCParser {
		rest, err := stripPRI(syslogLine.Message)
		if err != nil {
			return "", err
		}

		return strings.TrimSuffix(string(rest), "\n"), nil
	}

	var err3164, err5424 error
	p := rfc3164.NewRFC3164Parser(rfc3164.WithCurrentYear())

	err := p.Parse(syslogLine.Message)
	if err != nil {
		err3164 = err

		p2 := rfc5424.NewRFC5424Parser()

		err = p2.Parse(syslogLine.Message)
		if err != nil {
			return "", &ParseError{
				Reason:     ErrUnrecognized,
				RawMessage: syslogLine.Message,
				RFC3164:    err3164,
				RFC5424:    err5424,
			}
		}

		line = s.buildLogFromSyslog(p2.Timestamp, p2.Hostname, p2.Tag, p2.PID, p2.Message)
		if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
			metrics.SyslogDataSourceLinesParsed.With(prometheus.Labels{"source": syslogLine.Client, "type": "rfc5424", "datasource_type": ModuleName, "acquis_type": s.config.Labels["type"]}).Inc()
		}
	} else {
		line = s.buildLogFromSyslog(p.Timestamp, p.Hostname, p.Tag, p.PID, p.Message)
		if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
			metrics.SyslogDataSourceLinesParsed.With(prometheus.Labels{"source": syslogLine.Client, "type": "rfc3164", "datasource_type": ModuleName, "acquis_type": s.config.Labels["type"]}).Inc()
		}
	}

	return strings.TrimSuffix(line, "\n"), nil
}
