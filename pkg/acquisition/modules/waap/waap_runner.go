package wafacquisition

import (
	"fmt"
	"os"
	"time"

	"github.com/crowdsecurity/coraza/v3"
	"github.com/crowdsecurity/coraza/v3/experimental"
	corazatypes "github.com/crowdsecurity/coraza/v3/types"
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

func (r *WaapRunner) Init(datadir string) error {
	var err error
	fs := os.DirFS(datadir)

	inBandRules := ""
	outOfBandRules := ""

	for _, collection := range r.WaapRuntime.InBandRules {
		inBandRules += collection.String()
	}

	for _, collection := range r.WaapRuntime.OutOfBandRules {
		outOfBandRules += collection.String()
	}
	runnerLogger := r.logger.Dup()

	//setting up inband engine
	inbandCfg := coraza.NewWAFConfig().WithDirectives(inBandRules).WithRootFS(fs).WithDebugLogger(waf.NewCrzLogger(runnerLogger))
	if !r.WaapRuntime.Config.InbandOptions.DisableBodyInspection {
		inbandCfg = inbandCfg.WithRequestBodyAccess()
	} else {
		log.Warningf("Disabling body inspection, Inband rules will not be able to match on body's content.")
	}
	if r.WaapRuntime.Config.InbandOptions.RequestBodyInMemoryLimit != nil {
		inbandCfg = inbandCfg.WithRequestBodyInMemoryLimit(*r.WaapRuntime.Config.InbandOptions.RequestBodyInMemoryLimit)
	}
	r.WaapInbandEngine, err = coraza.NewWAF(inbandCfg)
	if err != nil {
		return fmt.Errorf("unable to initialize inband engine : %w", err)
	}

	//setting up outband engine
	outbandCfg := coraza.NewWAFConfig().WithDirectives(outOfBandRules).WithRootFS(fs).WithDebugLogger(waf.NewCrzLogger(runnerLogger))
	if !r.WaapRuntime.Config.OutOfBandOptions.DisableBodyInspection {
		outbandCfg = outbandCfg.WithRequestBodyAccess()
	} else {
		log.Warningf("Disabling body inspection, Out of band rules will not be able to match on body's content.")
	}
	if r.WaapRuntime.Config.OutOfBandOptions.RequestBodyInMemoryLimit != nil {
		outbandCfg = outbandCfg.WithRequestBodyInMemoryLimit(*r.WaapRuntime.Config.OutOfBandOptions.RequestBodyInMemoryLimit)
	}
	r.WaapOutbandEngine, err = coraza.NewWAF(outbandCfg)

	if err != nil {
		return fmt.Errorf("unable to initialize outband engine : %w", err)
	}

	return nil
}

func (r *WaapRunner) processRequest(tx experimental.FullTransaction, request *waf.ParsedRequest) error {
	var in *corazatypes.Interruption
	var err error
	request.Tx = tx

	if request.Tx.IsRuleEngineOff() {
		r.logger.Debugf("rule engine is off, skipping")
		return nil
	}

	defer func() {
		request.Tx.ProcessLogging()
		//We don't close the transaction here, as it will reset coraza internal state and break variable tracking
	}()

	request.Tx.ProcessConnection(request.RemoteAddr, 0, "", 0)

	for k, v := range request.Args {
		for _, vv := range v {
			request.Tx.AddGetRequestArgument(k, vv)
		}
	}

	request.Tx.ProcessURI(request.URI, request.Method, request.Proto) //TODO: The doc mentions that GET args needs to be added, but we never call AddArguments ?

	for k, vr := range request.Headers {
		for _, v := range vr {
			request.Tx.AddRequestHeader(k, v)
		}
	}

	if request.ClientHost != "" {
		request.Tx.AddRequestHeader("Host", request.ClientHost)
		request.Tx.SetServerName(request.ClientHost)
	}

	if request.TransferEncoding != nil {
		request.Tx.AddRequestHeader("Transfer-Encoding", request.TransferEncoding[0])
	}

	in = request.Tx.ProcessRequestHeaders()

	if in != nil {
		r.logger.Infof("inband rules matched for headers : %s", in.Action)
		return nil
	}

	if request.Body != nil && len(request.Body) > 0 {
		in, _, err = request.Tx.WriteRequestBody(request.Body)
		if err != nil {
			r.logger.Errorf("unable to write request body : %s", err)
			return err
		}
		if in != nil {
			return nil
		}
	}

	in, err = request.Tx.ProcessRequestBody()

	if err != nil {
		r.logger.Errorf("unable to process request body : %s", err)
		return err
	}

	if in != nil {
		r.logger.Infof("rules matched for body : %d", in.RuleID)
		return nil
	}

	return nil
}

func (r *WaapRunner) ProcessInBandRules(request *waf.ParsedRequest) error {
	tx := r.WaapInbandEngine.NewTransactionWithID(request.UUID)
	err := r.processRequest(tx.(experimental.FullTransaction), request)
	return err
}

func (r *WaapRunner) ProcessOutOfBandRules(request *waf.ParsedRequest) error {
	tx := r.WaapOutbandEngine.NewTransactionWithID(request.UUID)
	err := r.processRequest(tx.(experimental.FullTransaction), request)
	return err
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
			r.WaapRuntime.ClearResponse()

			request.IsInBand = true
			request.IsOutBand = false

			WafReqCounter.With(prometheus.Labels{"source": request.RemoteAddr}).Inc()
			//to measure the time spent in the WAF
			startParsing := time.Now()

			//pre eval (expr) rules
			err := r.WaapRuntime.ProcessPreEvalRules(request)
			if err != nil {
				r.logger.Errorf("unable to process PreEval rules: %s", err)
				continue
			}
			//inband WAAP rules
			err = r.ProcessInBandRules(&request)
			if err != nil {
				r.logger.Errorf("unable to process InBand rules: %s", err)
				continue
			}
			//create the associated event for crowdsec itself
			evt, err := EventFromRequest(request)
			if err != nil {
				//let's not interrupt the pipeline for this
				r.logger.Errorf("unable to create event from request : %s", err)
			}
			err = r.AccumulateTxToEvent(&evt, request)
			if err != nil {
				r.logger.Errorf("unable to accumulate tx to event : %s", err)
			}
			if in := request.Tx.Interruption(); in != nil {
				r.logger.Debugf("inband rules matched : %d", in.RuleID)
				r.WaapRuntime.Response.InBandInterrupt = true

				err = r.WaapRuntime.ProcessOnMatchRules(request)
				if err != nil {
					r.logger.Errorf("unable to process OnMatch rules: %s", err)
					continue
				}
			}
			elapsed := time.Since(startParsing)
			WafInbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(elapsed.Seconds())

			//generate reponse for the remediation component, based on the WAAP config + inband rules evaluation
			//@tko : this should move in the WaapRuntimeConfig as it knows what to do with the interruption and the expected remediation

			// send back the result to the HTTP handler for the InBand part
			request.ResponseChannel <- r.WaapRuntime.Response

			request.IsInBand = false
			request.IsOutBand = true

			err = r.ProcessOutOfBandRules(&request)
			if err != nil {
				r.logger.Errorf("unable to process OutOfBand rules: %s", err)
				continue
			}
			err = r.AccumulateTxToEvent(&evt, request)
			if err != nil {
				r.logger.Errorf("unable to accumulate tx to event : %s", err)
			}
			if in := request.Tx.Interruption(); in != nil {
				r.logger.Debugf("outband rules matched : %d", in.RuleID)
				r.WaapRuntime.Response.OutOfBandInterrupt = true
				err = r.WaapRuntime.ProcessOnMatchRules(request)
				if err != nil {
					r.logger.Errorf("unable to process OnMatch rules: %s", err)
					continue
				}
			}

			if !evt.Process {
				continue
			}

			//we generate two events: one that is going to be picked up by the acquisition pipeline (parsers, scenarios etc.)
			//and a second one that will go straight to LAPI
			r.outChan <- evt
			waapOvlfw, err := WaapEventGeneration(evt)
			if err != nil {
				r.logger.Errorf("unable to generate waap event : %s", err)
			} else {
				r.outChan <- waapOvlfw
			}
		}
	}
}
