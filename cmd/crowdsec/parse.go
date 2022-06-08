package main

import (
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func runParse(input chan types.Event, output chan types.Event, parserCTX parser.UnixParserCtx, nodes []parser.Node) error {

LOOP:
	for {
		select {
		case <-parsersTomb.Dying():
			log.Infof("Killing parser routines")
			break LOOP
		case event := <-input:
			if !event.Process {
				continue
			}
			if event.Line.Module == "" {
				log.Errorf("empty event.Line.Module field, the acquisition module must set it ! : %+v", event.Line)
				continue
			}
			globalParserHits.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Inc()

			/* parse the log using magic */
			parsed, err := parser.Parse(parserCTX, event, nodes)
			if err != nil {
				log.Errorf("failed parsing : %v\n", err)
			}
			if !parsed.Process {
				globalParserHitsKo.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Inc()
				log.Debugf("Discarding line %+v", parsed)
				continue
			}
			globalParserHitsOk.With(prometheus.Labels{"source": event.Line.Src, "type": event.Line.Module}).Inc()
			if parsed.Whitelisted {
				log.Debugf("event whitelisted, discard")
				continue
			}
			output <- parsed
		}
	}
	return nil
}
