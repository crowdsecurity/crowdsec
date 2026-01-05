package main

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func parseEvent(
	event pipeline.Event,
	parserCTX parser.UnixParserCtx,
	nodes []parser.Node,
) *pipeline.Event {
	if !event.Process {
		return nil
	}
	/*Application security engine is going to generate 2 events:
	- one that is treated as a log and can go to scenarios
	- another one that will go directly to LAPI*/
	if event.Type == pipeline.APPSEC {
		outEvents <- event
		return nil
	}
	if event.Line.Module == "" {
		log.Errorf("empty event.Line.Module field, the acquisition module must set it ! : %+v", event.Line)
		return nil
	}
	metrics.GlobalParserHits.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Inc()

	startParsing := time.Now()
	/* parse the log using magic */
	parsed, err := parser.Parse(parserCTX, event, nodes)
	if err != nil {
		log.Errorf("failed parsing: %v", err)
	}
	elapsed := time.Since(startParsing)
	metrics.GlobalParsingHistogram.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Observe(elapsed.Seconds())
	if !parsed.Process {
		metrics.GlobalParserHitsKo.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module, "acquis_type": event.Line.Labels["type"]}).Inc()
		log.Debugf("Discarding line %+v", parsed)
		return nil
	}
	metrics.GlobalParserHitsOk.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module, "acquis_type": event.Line.Labels["type"]}).Inc()
	if parsed.Whitelisted {
		log.Debugf("event whitelisted, discard")
		return nil
	}

	return &parsed
}

func runParse(ctx context.Context, input chan pipeline.Event, output chan pipeline.Event, parserCTX parser.UnixParserCtx, nodes []parser.Node) {
	for {
		select {
		case <-ctx.Done():
			log.Infof("Killing parser routines")
			return
		case event := <-input:
			parsed := parseEvent(event, parserCTX, nodes)
			if parsed == nil {
				continue
			}
			output <- *parsed
		}
	}
}
