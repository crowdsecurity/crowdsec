package wineventlogacquisition

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// 0 identifies the local machine in windows APIs
const localMachine = 0

// This is lifted from winops/winlog, but we only want to render the basic XML string, we don't need the extra fluff
func (s *Source) getXMLEvents(config *winlog.SubscribeConfig, publisherCache map[string]windows.Handle, resultSet windows.Handle, maxEvents int) ([]string, error) {
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
			s.logger.Errorf("Failed to render event with RenderFragment, skipping: %v", err)
			continue
		}
		s.logger.Tracef("Rendered event: %s", fragment)
		renderedEvents = append(renderedEvents, fragment)
	}
	return renderedEvents, err
}

func (s *Source) getEvents(out chan pipeline.Event, t *tomb.Tomb) error {
	subscription, err := winlog.Subscribe(s.evtConfig)
	if err != nil {
		s.logger.Errorf("Failed to subscribe to event log: %s", err)
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
			s.logger.Infof("wineventlog is dying")
			return nil
		default:
			status, err := windows.WaitForSingleObject(s.evtConfig.SignalEvent, 1000)
			if err != nil {
				s.logger.Errorf("WaitForSingleObject failed: %s", err)
				return err
			}
			if status == windows.WAIT_OBJECT_0 {
				renderedEvents, err := s.getXMLEvents(s.evtConfig, publisherCache, subscription, 500)
				if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
					windows.ResetEvent(s.evtConfig.SignalEvent)
				} else if err != nil {
					s.logger.Errorf("getXMLEvents failed: %v", err)
					continue
				}
				for _, event := range renderedEvents {
					if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.WineventlogDataSourceLinesRead.With(prometheus.Labels{"source": s.name, "datasource_type": "wineventlog", "acquis_type": s.config.Labels["type"]}).Inc()
					}
					l := pipeline.Line{}
					l.Raw = event
					l.Module = s.GetName()
					l.Labels = s.config.Labels
					l.Time = time.Now()
					l.Src = s.name
					l.Process = true
					if !s.config.UseTimeMachine {
						out <- pipeline.Event{Line: l, Process: true, Type: pipeline.LOG, ExpectMode: pipeline.LIVE, Unmarshaled: make(map[string]interface{})}
					} else {
						out <- pipeline.Event{Line: l, Process: true, Type: pipeline.LOG, ExpectMode: pipeline.TIMEMACHINE, Unmarshaled: make(map[string]interface{})}
					}
				}
			}

		}
	}
}

func (s *Source) OneShot(ctx context.Context, out chan pipeline.Event) error {
	handle, err := wevtapi.EvtQuery(localMachine, s.evtConfig.ChannelPath, s.evtConfig.Query, s.evtConfig.Flags)
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
		case <-ctx.Done():
			s.logger.Infof("wineventlog is dying")
			return nil
		default:
			evts, err := s.getXMLEvents(s.evtConfig, publisherCache, handle, 500)
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				log.Info("No more items")
				break OUTER_LOOP
			} else if err != nil {
				return fmt.Errorf("getXMLEvents failed: %v", err)
			}
			s.logger.Debugf("Got %d events", len(evts))
			for _, evt := range evts {
				s.logger.Tracef("Event: %s", evt)
				if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
					metrics.WineventlogDataSourceLinesRead.With(prometheus.Labels{"source": s.name, "datasource_type": "wineventlog", "acquis_type": s.config.Labels["type"]}).Inc()
				}
				l := pipeline.Line{}
				l.Raw = evt
				l.Module = s.GetName()
				l.Labels = s.config.Labels
				l.Time = time.Now()
				l.Src = s.name
				l.Process = true
				csevt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
				csevt.Line = l
				out <- csevt
			}
		}
	}

	return nil
}

func (s *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/wineventlog/streaming")
		return s.getEvents(out, t)
	})
	return nil
}
