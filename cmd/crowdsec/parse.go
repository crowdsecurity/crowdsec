package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func runParse(input chan types.Event, output chan types.Event, parserCTX parser.UnixParserCtx, nodes []parser.Node) error {
	for {
		select {
		case <-parsersTomb.Dying():
			log.Infof("Killing parser routines")
			return nil
		case event := <-input:
			if !event.Process {
				continue
			}
			/*Application security engine is going to generate 2 events:
			- one that is treated as a log and can go to scenarios
			- another one that will go directly to LAPI*/
			if event.Type == types.APPSEC {
				outputEventChan <- event
				continue
			}
			if event.Line.Module == "" {
				log.Errorf("empty event.Line.Module field, the acquisition module must set it ! : %+v", event.Line)
				continue
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
				continue
			}
			metrics.GlobalParserHitsOk.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module, "acquis_type": event.Line.Labels["type"]}).Inc()
			if parsed.Whitelisted {
				log.Debugf("event whitelisted, discard")
				continue
			}
			output <- parsed
		}
	}
}
