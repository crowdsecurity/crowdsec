package wafacquisition

import (
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/crowdsecurity/coraza/v3"
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
	inBandLogger := r.logger.Dup().WithField("band", "inband")
	outBandLogger := r.logger.Dup().WithField("band", "outband")

	//setting up inband engine
	inbandCfg := coraza.NewWAFConfig().WithDirectives(inBandRules).WithRootFS(fs).WithDebugLogger(waf.NewCrzLogger(inBandLogger))
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
	outbandCfg := coraza.NewWAFConfig().WithDirectives(outOfBandRules).WithRootFS(fs).WithDebugLogger(waf.NewCrzLogger(outBandLogger))
	if !r.WaapRuntime.Config.OutOfBandOptions.DisableBodyInspection {
		outbandCfg = outbandCfg.WithRequestBodyAccess()
	} else {
		log.Warningf("Disabling body inspection, Out of band rules will not be able to match on body's content.")
	}
	if r.WaapRuntime.Config.OutOfBandOptions.RequestBodyInMemoryLimit != nil {
		outbandCfg = outbandCfg.WithRequestBodyInMemoryLimit(*r.WaapRuntime.Config.OutOfBandOptions.RequestBodyInMemoryLimit)
	}
	r.WaapOutbandEngine, err = coraza.NewWAF(outbandCfg)

	if r.WaapRuntime.DisabledInBandRulesTags != nil {
		for _, tag := range r.WaapRuntime.DisabledInBandRulesTags {
			r.WaapInbandEngine.GetRuleGroup().DeleteByTag(tag)
		}
	}

	if r.WaapRuntime.DisabledOutOfBandRulesTags != nil {
		for _, tag := range r.WaapRuntime.DisabledOutOfBandRulesTags {
			r.WaapOutbandEngine.GetRuleGroup().DeleteByTag(tag)
		}
	}

	if r.WaapRuntime.DisabledInBandRuleIds != nil {
		for _, id := range r.WaapRuntime.DisabledInBandRuleIds {
			r.WaapInbandEngine.GetRuleGroup().DeleteByID(id)
		}
	}

	if r.WaapRuntime.DisabledOutOfBandRuleIds != nil {
		for _, id := range r.WaapRuntime.DisabledOutOfBandRuleIds {
			r.WaapOutbandEngine.GetRuleGroup().DeleteByID(id)
		}
	}

	if err != nil {
		return fmt.Errorf("unable to initialize outband engine : %w", err)
	}

	return nil
}

func (r *WaapRunner) processRequest(tx waf.ExtendedTransaction, request *waf.ParsedRequest) error {
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

	//pre eval (expr) rules
	err = r.WaapRuntime.ProcessPreEvalRules(request)
	if err != nil {
		r.logger.Errorf("unable to process PreEval rules: %s", err)
		//FIXME: should we abort here ?
	}

	request.Tx.Tx.ProcessConnection(request.RemoteAddr, 0, "", 0)

	for k, v := range request.Args {
		for _, vv := range v {
			request.Tx.AddGetRequestArgument(k, vv)
		}
	}

	request.Tx.ProcessURI(request.URI, request.Method, request.Proto)

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
		r.logger.Debugf("rules matched for body : %d", in.RuleID)
	}

	err = r.WaapRuntime.ProcessPostEvalRules(request)
	if err != nil {
		r.logger.Errorf("unable to process PostEval rules: %s", err)
	}

	return nil
}

func (r *WaapRunner) ProcessInBandRules(request *waf.ParsedRequest) error {
	tx := waf.NewExtendedTransaction(r.WaapInbandEngine, request.UUID)
	r.WaapRuntime.InBandTx = tx
	err := r.processRequest(tx, request)
	return err
}

func (r *WaapRunner) ProcessOutOfBandRules(request *waf.ParsedRequest) error {
	tx := waf.NewExtendedTransaction(r.WaapOutbandEngine, request.UUID)
	r.WaapRuntime.OutOfBandTx = tx
	err := r.processRequest(tx, request)
	return err
}

func (r *WaapRunner) handleInBandInterrupt(request *waf.ParsedRequest) {
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
		r.WaapRuntime.Response.HTTPResponseCode = r.WaapRuntime.Config.BlockedHTTPCode
		r.WaapRuntime.Response.Action = r.WaapRuntime.DefaultRemediation

		if _, ok := r.WaapRuntime.RemediationById[in.RuleID]; ok {
			r.WaapRuntime.Response.Action = r.WaapRuntime.RemediationById[in.RuleID]
		}

		for tag, remediation := range r.WaapRuntime.RemediationByTag {
			if slices.Contains[[]string, string](in.Tags, tag) {
				r.WaapRuntime.Response.Action = remediation
			}
		}

		err = r.WaapRuntime.ProcessOnMatchRules(request, evt)
		if err != nil {
			r.logger.Errorf("unable to process OnMatch rules: %s", err)
			return
		}
		// Should the in band match trigger an event ?
		if r.WaapRuntime.Response.SendEvent {
			r.outChan <- evt
		}

		// Should the in band match trigger an overflow ?
		if r.WaapRuntime.Response.SendAlert {
			waapOvlfw, err := WaapEventGeneration(evt)
			if err != nil {
				r.logger.Errorf("unable to generate waap event : %s", err)
				return
			}
			r.outChan <- *waapOvlfw
		}
	}
}

func (r *WaapRunner) handleOutBandInterrupt(request *waf.ParsedRequest) {
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
		r.WaapRuntime.Response.OutOfBandInterrupt = true

		err = r.WaapRuntime.ProcessOnMatchRules(request, evt)
		if err != nil {
			r.logger.Errorf("unable to process OnMatch rules: %s", err)
			return
		}
		// Should the match trigger an event ?
		if r.WaapRuntime.Response.SendEvent {
			r.outChan <- evt
		}

		// Should the match trigger an overflow ?
		if r.WaapRuntime.Response.SendAlert {
			waapOvlfw, err := WaapEventGeneration(evt)
			if err != nil {
				r.logger.Errorf("unable to generate waap event : %s", err)
				return
			}
			r.outChan <- *waapOvlfw
		}
	}
}

func (r *WaapRunner) handleRequest(request *waf.ParsedRequest) {
	r.logger.Debugf("Requests handled by runner %s", request.UUID)
	r.WaapRuntime.ClearResponse()

	request.IsInBand = true
	request.IsOutBand = false

	//to measure the time spent in the WAF
	startParsing := time.Now()

	//inband WAAP rules
	err := r.ProcessInBandRules(request)
	if err != nil {
		r.logger.Errorf("unable to process InBand rules: %s", err)
		return
	}

	if request.Tx.IsInterrupted() {
		r.handleInBandInterrupt(request)
	}

	elapsed := time.Since(startParsing)
	WafInbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(elapsed.Seconds())

	// send back the result to the HTTP handler for the InBand part
	request.ResponseChannel <- r.WaapRuntime.Response

	//Now let's process the out of band rules

	request.IsInBand = false
	request.IsOutBand = true
	r.WaapRuntime.Response.SendAlert = false
	r.WaapRuntime.Response.SendEvent = true

	err = r.ProcessOutOfBandRules(request)
	if err != nil {
		r.logger.Errorf("unable to process OutOfBand rules: %s", err)
		return
	}

	if request.Tx.IsInterrupted() {
		r.handleOutBandInterrupt(request)
	}
}

func (r *WaapRunner) Run(t *tomb.Tomb) error {
	r.logger.Infof("Waap Runner ready to process event")
	for {
		select {
		case <-t.Dying():
			r.logger.Infof("Waf Runner is dying")
			return nil
		case request := <-r.inChan:
			r.handleRequest(&request)
		}
	}
}
