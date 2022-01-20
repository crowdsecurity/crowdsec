package wineventlogacquisition

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type WinEventLogConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	EventChannel                      string `yaml:"event_channel"`
	EventSource                       string `yaml:"event_source"`
	EventLevel                        string `yaml:"event_level"`
	EventIDs                          []int  `yaml:"event_ids"`
	XPathQuery                        string `yaml:"xpath_query"`
	EventFile                         string `yaml:"event_file"`
}

type WinEventLogSource struct {
	config    WinEventLogConfiguration
	logger    *log.Entry
	evtConfig *winlog.SubscribeConfig
	query     string
}

func (w *WinEventLogSource) buildXpathQuery() string {
	return ""
}

func (w *WinEventLogSource) getEvents(out chan types.Event, t *tomb.Tomb) error {
	subscription, err := winlog.Subscribe(w.evtConfig)
	if err != nil {
		log.Fatalf("winlog.Subscribe 1: %v", err)
	}
	defer winlog.Close(subscription)
	publisherCache := make(map[string]windows.Handle)
	defer func() {
		for _, h := range publisherCache {
			winlog.Close(h)
		}
	}()
	w.logger.Info("in getevents")
	for {
		select {
		case <-t.Dying():
			w.logger.Infof("wineventlog is dying")
			return nil
		default:
			w.logger.Info("in getevents for loop")
			status, err := windows.WaitForSingleObject(w.evtConfig.SignalEvent, 1000)
			if err != nil {
				fmt.Fprintf(os.Stderr, "windows.WaitForSingleObject failed: %v", err)
				return err
			}
			// Get a block of events once signaled.
			if status == syscall.WAIT_OBJECT_0 {
				// Enumerate and render available events in blocks of up to 100.
				renderedEvents, err := winlog.GetRenderedEvents(w.evtConfig, publisherCache, subscription, 100, 1033)
				// If no more events are available reset the subscription signal.
				if err == syscall.Errno(259) { // ERROR_NO_MORE_ITEMS
					windows.ResetEvent(w.evtConfig.SignalEvent)
				} else if err != nil {
					fmt.Fprintf(os.Stderr, "winlog.GetRenderedEvents failed: %v", err)
					return err
				}
				// Print the events.
				for _, event := range renderedEvents {
					fmt.Println(event)
					fmt.Printf("-----------------------\n")
				}
			}

		}
	}
	return nil
}

func (w *WinEventLogSource) generateConfig(query string) (*winlog.SubscribeConfig, error) {
	var config winlog.SubscribeConfig
	var err error

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
	/*xpaths := map[string]string{"Application": "*"}
	xmlQuery, err := winlog.BuildStructuredXMLQuery(xpaths)
	if err != nil {
		return nil, fmt.Errorf("BuildStructuredXMLQuery failed: %v", err)
	}*/

	config.Query, err = syscall.UTF16PtrFromString(query)
	if err != nil {
		return &config, fmt.Errorf("syscall.UTF16PtrFromString failed: %v", err)
	}

	return &config, nil
}

func (w *WinEventLogSource) Configure(yamlConfig []byte, logger *log.Entry) error {

	config := WinEventLogConfiguration{}
	w.logger = logger
	err := yaml.UnmarshalStrict(yamlConfig, &config)

	if err != nil {
		return fmt.Errorf("unable to parse configuration: %v", err)
	}

	if config.EventChannel != "" && config.EventSource != "" {
		return fmt.Errorf("event_channel and event_source are mutually exclusive")
	}

	if config.EventChannel == "" && config.EventSource == "" {
		return fmt.Errorf("event_channel or event_source must be set")
	}

	if config.XPathQuery != "" {
		w.query = config.XPathQuery
	} else {
		w.query = w.buildXpathQuery()
	}
	config.Mode = configuration.TAIL_MODE
	w.config = config

	w.evtConfig, err = w.generateConfig(w.query)
	if err != nil {
		return err
	}
	/*err = winlog.GetBookmarkRegistry(config, registry.CURRENT_USER, `SOFTWARE\Logging`, "Bookmark")
	if err != nil {
		log.Fatalf("winlog.GetBookmarkRegistry failed: %v", err)
	}
	config.Flags = wevtapi.EvtSubscribeStartAfterBookmark*/

	return nil
}

func (w *WinEventLogSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	return nil
}

func (w *WinEventLogSource) GetMode() string {
	return w.config.Mode
}

func (w *WinEventLogSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (w *WinEventLogSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return nil
}

func (w *WinEventLogSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (w *WinEventLogSource) GetAggregMetrics() []prometheus.Collector {
	return nil
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

func (w *WinEventLogSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/wineventlog/streaming")
		return w.getEvents(out, t)
	})
	return nil
}

func (w *WinEventLogSource) Dump() interface{} {
	return w
}
