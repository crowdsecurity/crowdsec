package wineventlogacquisition

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type WinEventLogConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	EventChannel                      string `yaml:"event_channel"`
	EventLevel                        string `yaml:"event_level"`
	EventIDs                          []int  `yaml:"event_ids"`
	XPathQuery                        string `yaml:"xpath_query"`
	EventFile                         string
	PrettyName                        string `yaml:"pretty_name"`
}

type WinEventLogSource struct {
	metricsLevel int
	config       WinEventLogConfiguration
	logger       *log.Entry
	evtConfig    *winlog.SubscribeConfig
	query        string
	name         string
}

type QueryList struct {
	Select Select `xml:"Query>Select"`
}

type Select struct {
	Path  string `xml:"Path,attr,omitempty"`
	Query string `xml:",chardata"`
}

// 0 identifies the local machine in windows APIs
const localMachine = 0

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_winevtlogsource_hits_total",
		Help: "Total event that were read.",
	},
	[]string{"source"})

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

// This is lifted from winops/winlog, but we only want to render the basic XML string, we don't need the extra fluff
func (w *WinEventLogSource) getXMLEvents(config *winlog.SubscribeConfig, publisherCache map[string]windows.Handle, resultSet windows.Handle, maxEvents int) ([]string, error) {
	events := make([]windows.Handle, maxEvents)
	var returned uint32

	// Get handles to events from the result set.
	err := wevtapi.EvtNext(
		resultSet,           // Handle to query or subscription result set.
		uint32(len(events)), // The number of events to attempt to retrieve.
		&events[0],          // Pointer to the array of event handles.
		2000,                // Timeout in milliseconds to wait.
		0,                   // Reserved. Must be zero.
		&returned)           // The number of handles in the array that are set by the API.
	if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("wevtapi.EvtNext failed: %v", err)
	}

	// Event handles must be closed after they are returned by EvtNext whether or not we use them.
	defer func() {
		for _, event := range events[:returned] {
			winlog.Close(event)
		}
	}()

	// Render events.
	var renderedEvents []string
	for _, event := range events[:returned] {
		// Render the basic XML representation of the event.
		fragment, err := winlog.RenderFragment(event, wevtapi.EvtRenderEventXml)
		if err != nil {
			w.logger.Errorf("Failed to render event with RenderFragment, skipping: %v", err)
			continue
		}
		w.logger.Tracef("Rendered event: %s", fragment)
		renderedEvents = append(renderedEvents, fragment)
	}
	return renderedEvents, err
}

func (w *WinEventLogSource) buildXpathQuery() (string, error) {
	var query string
	queryComponents := [][]string{}
	if w.config.EventIDs != nil {
		eventIds := []string{}
		for _, id := range w.config.EventIDs {
			eventIds = append(eventIds, fmt.Sprintf("EventID=%d", id))
		}
		queryComponents = append(queryComponents, eventIds)
	}
	if w.config.EventLevel != "" {
		levels, err := logLevelToInt(w.config.EventLevel)
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
	queryList := QueryList{Select: Select{Path: w.config.EventChannel, Query: query}}
	xpathQuery, err := xml.Marshal(queryList)
	if err != nil {
		w.logger.Errorf("Serialize failed: %v", err)
		return "", err
	}
	w.logger.Debugf("xpathQuery: %s", xpathQuery)
	return string(xpathQuery), nil
}

func (w *WinEventLogSource) getEvents(out chan types.Event, t *tomb.Tomb) error {
	subscription, err := winlog.Subscribe(w.evtConfig)
	if err != nil {
		w.logger.Errorf("Failed to subscribe to event log: %s", err)
		return err
	}
	defer winlog.Close(subscription)
	publisherCache := make(map[string]windows.Handle)
	defer func() {
		for _, h := range publisherCache {
			winlog.Close(h)
		}
	}()
	for {
		select {
		case <-t.Dying():
			w.logger.Infof("wineventlog is dying")
			return nil
		default:
			status, err := windows.WaitForSingleObject(w.evtConfig.SignalEvent, 1000)
			if err != nil {
				w.logger.Errorf("WaitForSingleObject failed: %s", err)
				return err
			}
			if status == syscall.WAIT_OBJECT_0 {
				renderedEvents, err := w.getXMLEvents(w.evtConfig, publisherCache, subscription, 500)
				if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
					windows.ResetEvent(w.evtConfig.SignalEvent)
				} else if err != nil {
					w.logger.Errorf("getXMLEvents failed: %v", err)
					continue
				}
				for _, event := range renderedEvents {
					if w.metricsLevel != configuration.METRICS_NONE {
						linesRead.With(prometheus.Labels{"source": w.name}).Inc()
					}
					l := types.Line{}
					l.Raw = event
					l.Module = w.GetName()
					l.Labels = w.config.Labels
					l.Time = time.Now()
					l.Src = w.name
					l.Process = true
					if !w.config.UseTimeMachine {
						out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE, Unmarshaled: make(map[string]interface{})}
					} else {
						out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE, Unmarshaled: make(map[string]interface{})}
					}
				}
			}

		}
	}
}

func (w *WinEventLogSource) generateConfig(query string, live bool) (*winlog.SubscribeConfig, error) {
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
		config.ChannelPath, err = syscall.UTF16PtrFromString(w.config.EventFile)
		if err != nil {
			return &config, fmt.Errorf("syscall.UTF16PtrFromString failed: %v", err)
		}
		config.Flags = wevtapi.EvtQueryFilePath | wevtapi.EvtQueryForwardDirection
	}
	config.Query, err = syscall.UTF16PtrFromString(query)
	if err != nil {
		return &config, fmt.Errorf("syscall.UTF16PtrFromString failed: %v", err)
	}

	return &config, nil
}

func (w *WinEventLogSource) GetUuid() string {
	return w.config.UniqueId
}

func (w *WinEventLogSource) UnmarshalConfig(yamlConfig []byte) error {
	w.config = WinEventLogConfiguration{}

	err := yaml.UnmarshalStrict(yamlConfig, &w.config)
	if err != nil {
		return fmt.Errorf("unable to parse configuration: %v", err)
	}

	if w.config.EventChannel != "" && w.config.XPathQuery != "" {
		return errors.New("event_channel and xpath_query are mutually exclusive")
	}

	if w.config.EventChannel == "" && w.config.XPathQuery == "" {
		return errors.New("event_channel or xpath_query must be set")
	}

	w.config.Mode = configuration.TAIL_MODE

	if w.config.XPathQuery != "" {
		w.query = w.config.XPathQuery
	} else {
		w.query, err = w.buildXpathQuery()
		if err != nil {
			return fmt.Errorf("buildXpathQuery failed: %v", err)
		}
	}

	if w.config.PrettyName != "" {
		w.name = w.config.PrettyName
	} else {
		w.name = w.query
	}

	return nil
}

func (w *WinEventLogSource) Configure(yamlConfig []byte, logger *log.Entry, metricsLevel int) error {
	w.logger = logger
	w.metricsLevel = metricsLevel

	err := w.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	w.evtConfig, err = w.generateConfig(w.query, true)
	if err != nil {
		return err
	}

	return nil
}

func (w *WinEventLogSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	if !strings.HasPrefix(dsn, "wineventlog://") {
		return fmt.Errorf("invalid DSN %s for wineventlog source, must start with wineventlog://", dsn)
	}

	w.logger = logger
	w.config = WinEventLogConfiguration{}

	dsn = strings.TrimPrefix(dsn, "wineventlog://")

	args := strings.Split(dsn, "?")

	if args[0] == "" {
		return errors.New("empty wineventlog:// DSN")
	}

	if len(args) > 2 {
		return errors.New("too many arguments in DSN")
	}

	w.config.EventFile = args[0]

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
				w.logger.Logger.SetLevel(lvl)
			case "event_id":
				for _, id := range value {
					evtid, err := strconv.Atoi(id)
					if err != nil {
						return fmt.Errorf("failed to parse event_id: %s", err)
					}
					w.config.EventIDs = append(w.config.EventIDs, evtid)
				}
			case "event_level":
				if len(value) != 1 {
					return errors.New("event_level must be a single value")
				}
				w.config.EventLevel = value[0]
			}
		}
	}

	var err error

	// FIXME: handle custom xpath query
	w.query, err = w.buildXpathQuery()

	if err != nil {
		return fmt.Errorf("buildXpathQuery failed: %w", err)
	}

	w.logger.Debugf("query: %s\n", w.query)

	w.evtConfig, err = w.generateConfig(w.query, false)

	if err != nil {
		return fmt.Errorf("generateConfig failed: %w", err)
	}

	return nil
}

func (w *WinEventLogSource) GetMode() string {
	return w.config.Mode
}

func (w *WinEventLogSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (w *WinEventLogSource) OneShotAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	handle, err := wevtapi.EvtQuery(localMachine, w.evtConfig.ChannelPath, w.evtConfig.Query, w.evtConfig.Flags)
	if err != nil {
		return fmt.Errorf("EvtQuery failed: %v", err)
	}

	defer winlog.Close(handle)

	publisherCache := make(map[string]windows.Handle)
	defer func() {
		for _, h := range publisherCache {
			winlog.Close(h)
		}
	}()

OUTER_LOOP:
	for {
		select {
		case <-t.Dying():
			w.logger.Infof("wineventlog is dying")
			return nil
		default:
			evts, err := w.getXMLEvents(w.evtConfig, publisherCache, handle, 500)
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				log.Info("No more items")
				break OUTER_LOOP
			} else if err != nil {
				return fmt.Errorf("getXMLEvents failed: %v", err)
			}
			w.logger.Debugf("Got %d events", len(evts))
			for _, evt := range evts {
				w.logger.Tracef("Event: %s", evt)
				if w.metricsLevel != configuration.METRICS_NONE {
					linesRead.With(prometheus.Labels{"source": w.name}).Inc()
				}
				l := types.Line{}
				l.Raw = evt
				l.Module = w.GetName()
				l.Labels = w.config.Labels
				l.Time = time.Now()
				l.Src = w.name
				l.Process = true
				csevt := types.MakeEvent(w.config.UseTimeMachine, types.LOG, true)
				csevt.Line = l
				out <- csevt
			}
		}
	}

	return nil
}

func (w *WinEventLogSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (w *WinEventLogSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (w *WinEventLogSource) GetName() string {
	return "wineventlog"
}

func (w *WinEventLogSource) CanRun() error {
	if runtime.GOOS != "windows" {
		return errors.New("windows event log acquisition is only supported on Windows")
	}
	return nil
}

func (w *WinEventLogSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/wineventlog/streaming")
		return w.getEvents(out, t)
	})
	return nil
}

func (w *WinEventLogSource) Dump() interface{} {
	return w
}
