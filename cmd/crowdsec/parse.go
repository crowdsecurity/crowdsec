package main

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func runParse(input chan types.Event, output chan types.Event, parserCTX parser.UnixParserCtx, nodes []parser.Node) error {
	var start time.Time
	var discardCPT, processCPT int

LOOP:
	for {
		select {
		case <-parsersTomb.Dying():
			log.Infof("Killing parser routines")
			break LOOP
		case event := <-input:
			if cConfig.Profiling {
				start = time.Now()
			}
			if !event.Process {
				if cConfig.Profiling {
					atomic.AddUint64(&linesReadKO, 1)
				}
				continue
			}
			if cConfig.Profiling {
				atomic.AddUint64(&linesReadOK, 1)
			}
			globalParserHits.With(prometheus.Labels{"source": event.Line.Src}).Inc()

			/* parse the log using magic */
			parsed, error := parser.Parse(parserCTX, event, nodes)
			if error != nil {
				log.Errorf("failed parsing : %v\n", error)
				return errors.New("parsing failed :/")
			}
			if !parsed.Process {
				if cConfig.Profiling {
					atomic.AddUint64(&linesParsedKO, 1)
				}
				globalParserHitsKo.With(prometheus.Labels{"source": event.Line.Src}).Inc()
				log.Debugf("Discarding line %+v", parsed)
				discardCPT++
				continue
			}
			if cConfig.Profiling {
				atomic.AddUint64(&linesParsedOK, 1)
			}
			globalParserHitsOk.With(prometheus.Labels{"source": event.Line.Src}).Inc()
			processCPT++
			if parsed.Whitelisted {
				log.Debugf("event whitelisted, discard")
				continue
			}
			if processCPT%1000 == 0 {
				log.Debugf("%d lines processed, %d lines discarded (unparsed)", processCPT, discardCPT)
			}
			output <- parsed
			if cConfig.Profiling {
				parseStat.AddTime(time.Since(start))
			}
		}
	}
	return nil
}
