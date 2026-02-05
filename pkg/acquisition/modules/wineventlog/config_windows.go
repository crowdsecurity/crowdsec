package wineventlogacquisition

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	yaml "github.com/goccy/go-yaml"
	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	EventChannel                      string `yaml:"event_channel"`
	EventLevel                        string `yaml:"event_level"`
	EventIDs                          []int  `yaml:"event_ids"`
	XPathQuery                        string `yaml:"xpath_query"`
	EventFile                         string
	PrettyName                        string `yaml:"pretty_name"`
}

type QueryList struct {
	Select Select `xml:"Query>Select"`
}

type Select struct {
	Path  string `xml:"Path,attr,omitempty"`
	Query string `xml:",chardata"`
}

func logLevelToInt(logLevel string) ([]string, error) {
	switch strings.ToUpper(logLevel) {
	case "CRITICAL":
		return []string{"1"}, nil
	case "ERROR":
		return []string{"2"}, nil
	case "WARNING":
		return []string{"3"}, nil
	case "INFORMATION":
		return []string{"0", "4"}, nil
	case "VERBOSE":
		return []string{"5"}, nil
	default:
		return nil, errors.New("invalid log level")
	}
}

func (s *Source) buildXpathQuery() (string, error) {
	var query string
	queryComponents := [][]string{}
	if s.config.EventIDs != nil {
		eventIds := []string{}
		for _, id := range s.config.EventIDs {
			eventIds = append(eventIds, fmt.Sprintf("EventID=%d", id))
		}
		queryComponents = append(queryComponents, eventIds)
	}
	if s.config.EventLevel != "" {
		levels, err := logLevelToInt(s.config.EventLevel)
		logLevels := []string{}
		if err != nil {
			return "", err
		}
		for _, level := range levels {
			logLevels = append(logLevels, fmt.Sprintf("Level=%s", level))
		}
		queryComponents = append(queryComponents, logLevels)
	}
	if len(queryComponents) > 0 {
		andList := []string{}
		for _, component := range queryComponents {
			andList = append(andList, fmt.Sprintf("(%s)", strings.Join(component, " or ")))
		}
		query = fmt.Sprintf("*[System[%s]]", strings.Join(andList, " and "))
	} else {
		query = "*"
	}
	queryList := QueryList{Select: Select{Path: s.config.EventChannel, Query: query}}
	xpathQuery, err := xml.Marshal(queryList)
	if err != nil {
		if s.logger != nil {
			s.logger.Errorf("Failed to marshal XPath query: %v", err)
		}
		s.logger.Errorf("Serialize failed: %v", err)
		return "", err
	}
	if s.logger != nil {
		s.logger.Debugf("xpathQuery: %s", xpathQuery)
	}
	return string(xpathQuery), nil
}

func (s *Source) generateConfig(query string, live bool) (*winlog.SubscribeConfig, error) {
	var config winlog.SubscribeConfig
	var err error

	if live {
		// Create a subscription signaler.
		config.SignalEvent, err = windows.CreateEvent(
			nil, // Default security descriptor.
			1,   // Manual reset.
			1,   // Initial state is signaled.
			nil) // Optional name.
		if err != nil {
			return &config, fmt.Errorf("windows.CreateEvent failed: %v", err)
		}
		config.Flags = wevtapi.EvtSubscribeToFutureEvents
	} else {
		config.ChannelPath, err = windows.UTF16PtrFromString(s.config.EventFile)
		if err != nil {
			return &config, fmt.Errorf("windows.UTF16PtrFromString failed: %v", err)
		}
		config.Flags = wevtapi.EvtQueryFilePath | wevtapi.EvtQueryForwardDirection
	}
	config.Query, err = windows.UTF16PtrFromString(query)
	if err != nil {
		return &config, fmt.Errorf("windows.UTF16PtrFromString failed: %v", err)
	}

	return &config, nil
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.config = Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse wineventlog configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.config.EventChannel != "" && s.config.XPathQuery != "" {
		return errors.New("event_channel and xpath_query are mutually exclusive")
	}

	if s.config.EventChannel == "" && s.config.XPathQuery == "" {
		return errors.New("event_channel or xpath_query must be set")
	}

	s.config.Mode = configuration.TAIL_MODE

	if s.config.XPathQuery != "" {
		s.query = s.config.XPathQuery
	} else {
		s.query, err = s.buildXpathQuery()
		if err != nil {
			return fmt.Errorf("buildXpathQuery failed: %v", err)
		}
	}

	if s.config.PrettyName != "" {
		s.name = s.config.PrettyName
	} else {
		s.name = s.query
	}

	return nil
}

func (s *Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	s.evtConfig, err = s.generateConfig(s.query, true)
	if err != nil {
		return err
	}

	return nil
}

func (s *Source) ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	if !strings.HasPrefix(dsn, "wineventlog://") {
		return fmt.Errorf("invalid DSN %s for wineventlog source, must start with wineventlog://", dsn)
	}

	s.logger = logger
	s.config = Configuration{}

	dsn = strings.TrimPrefix(dsn, "wineventlog://")

	args := strings.Split(dsn, "?")

	if args[0] == "" {
		return errors.New("empty wineventlog:// DSN")
	}

	if len(args) > 2 {
		return errors.New("too many arguments in DSN")
	}

	s.config.EventFile = args[0]

	if len(args) == 2 && args[1] != "" {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return fmt.Errorf("failed to parse DSN parameters: %w", err)
		}

		for key, value := range params {
			switch key {
			case "log_level":
				if len(value) != 1 {
					return errors.New("log_level must be a single value")
				}
				lvl, err := log.ParseLevel(value[0])
				if err != nil {
					return fmt.Errorf("failed to parse log_level: %s", err)
				}
				s.logger.Logger.SetLevel(lvl)
			case "event_id":
				for _, id := range value {
					evtid, err := strconv.Atoi(id)
					if err != nil {
						return fmt.Errorf("failed to parse event_id: %s", err)
					}
					s.config.EventIDs = append(s.config.EventIDs, evtid)
				}
			case "event_level":
				if len(value) != 1 {
					return errors.New("event_level must be a single value")
				}
				s.config.EventLevel = value[0]
			}
		}
	}

	var err error

	// FIXME: handle custom xpath query
	s.query, err = s.buildXpathQuery()
	if err != nil {
		return fmt.Errorf("buildXpathQuery failed: %w", err)
	}

	s.logger.Debugf("query: %s\n", s.query)

	s.evtConfig, err = s.generateConfig(s.query, false)
	if err != nil {
		return fmt.Errorf("generateConfig failed: %w", err)
	}

	return nil
}
