package wafacquisition

import (
	"time"

	"github.com/crowdsecurity/coraza/v3"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

// that's the runtime structure of the WAAP as seen from the acquis
type WaapRunner struct {
	outChan           chan types.Event
	inChan            chan waf.ParsedRequest
	UUID              string
	WaapRuntime       *waf.WaapRuntimeConfig //this holds the actual waap runtime config, rules, remediations, hooks etc.
	WaapInbandEngine  coraza.WAF
	WaapOutbandEngine coraza.WAF
	logger            *log.Entry
}

func (r *WaapRunner) Run(t *tomb.Tomb) error {
	r.logger.Infof("Waap Runner ready to process event")
	for {
		select {
		case <-t.Dying():
			r.logger.Infof("Waf Runner is dying")
			return nil
		case request := <-r.inChan:
			r.logger.Infof("Requests handled by runner %s", request.UUID)

			//tx := waf.NewExtendedTransaction(r.WaapInbandEngine, r.UUID)
			WafReqCounter.With(prometheus.Labels{"source": request.RemoteAddr}).Inc()
			//measure the time spent in the WAF
			startParsing := time.Now()

			//pre eval (expr) rules
			err := r.WaapRuntime.ProcessPreEvalRules(request)
			if err != nil {
				r.logger.Errorf("unable to process PreEval rules: %s", err)
				continue
			}

			//inband WAAP rules
			interrupt, err := r.WaapRuntime.ProcessInBandRules(request)
			elapsed := time.Since(startParsing)
			WafInbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(elapsed.Seconds())

			//generate reponse for the remediation component, based on the WAAP config + inband rules evaluation
			//@tko : this should move in the WaapRuntimeConfig as it knows what to do with the interruption and the expected remediation
			response := waf.NewResponseRequest(r.WaapRuntime.InBandTx.Tx, interrupt, request.UUID, err)

			err = r.WaapRuntime.ProcessOnMatchRules(request, response)
			if err != nil {
				r.logger.Errorf("unable to process OnMatch rules: %s", err)
				continue
			}

			// send back the result to the HTTP handler for the InBand part
			request.ResponseChannel <- response

		}
	}
}
