package appsecacquisition

import (
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/crowdsecurity/coraza/v3"
	corazatypes "github.com/crowdsecurity/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	_ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec/bodyprocessors"
)

// that's the runtime structure of the Application security engine as seen from the acquis
type AppsecRunner struct {
	outChan             chan types.Event
	inChan              chan appsec.ParsedRequest
	UUID                string
	AppsecRuntime       *appsec.AppsecRuntimeConfig //this holds the actual appsec runtime config, rules, remediations, hooks etc.
	AppsecInbandEngine  coraza.WAF
	AppsecOutbandEngine coraza.WAF
	Labels              map[string]string
	logger              *log.Entry
}

func (r *AppsecRunner) Init(datadir string) error {
	var err error
	fs := os.DirFS(datadir)

	inBandRules := ""
	outOfBandRules := ""

	for _, collection := range r.AppsecRuntime.InBandRules {
		inBandRules += collection.String()
	}

	for _, collection := range r.AppsecRuntime.OutOfBandRules {
		outOfBandRules += collection.String()
	}
	inBandLogger := r.logger.Dup().WithField("band", "inband")
	outBandLogger := r.logger.Dup().WithField("band", "outband")

	//setting up inband engine
	inbandCfg := coraza.NewWAFConfig().WithDirectives(inBandRules).WithRootFS(fs).WithDebugLogger(appsec.NewCrzLogger(inBandLogger))
	if !r.AppsecRuntime.Config.InbandOptions.DisableBodyInspection {
		inbandCfg = inbandCfg.WithRequestBodyAccess()
	} else {
		log.Warningf("Disabling body inspection, Inband rules will not be able to match on body's content.")
	}
	if r.AppsecRuntime.Config.InbandOptions.RequestBodyInMemoryLimit != nil {
		inbandCfg = inbandCfg.WithRequestBodyInMemoryLimit(*r.AppsecRuntime.Config.InbandOptions.RequestBodyInMemoryLimit)
	}
	r.AppsecInbandEngine, err = coraza.NewWAF(inbandCfg)
	if err != nil {
		return fmt.Errorf("unable to initialize inband engine : %w", err)
	}

	//setting up outband engine
	outbandCfg := coraza.NewWAFConfig().WithDirectives(outOfBandRules).WithRootFS(fs).WithDebugLogger(appsec.NewCrzLogger(outBandLogger))
	if !r.AppsecRuntime.Config.OutOfBandOptions.DisableBodyInspection {
		outbandCfg = outbandCfg.WithRequestBodyAccess()
	} else {
		log.Warningf("Disabling body inspection, Out of band rules will not be able to match on body's content.")
	}
	if r.AppsecRuntime.Config.OutOfBandOptions.RequestBodyInMemoryLimit != nil {
		outbandCfg = outbandCfg.WithRequestBodyInMemoryLimit(*r.AppsecRuntime.Config.OutOfBandOptions.RequestBodyInMemoryLimit)
	}
	r.AppsecOutbandEngine, err = coraza.NewWAF(outbandCfg)

	if r.AppsecRuntime.DisabledInBandRulesTags != nil {
		for _, tag := range r.AppsecRuntime.DisabledInBandRulesTags {
			r.AppsecInbandEngine.GetRuleGroup().DeleteByTag(tag)
		}
	}

	if r.AppsecRuntime.DisabledOutOfBandRulesTags != nil {
		for _, tag := range r.AppsecRuntime.DisabledOutOfBandRulesTags {
			r.AppsecOutbandEngine.GetRuleGroup().DeleteByTag(tag)
		}
	}

	if r.AppsecRuntime.DisabledInBandRuleIds != nil {
		for _, id := range r.AppsecRuntime.DisabledInBandRuleIds {
			r.AppsecInbandEngine.GetRuleGroup().DeleteByID(id)
		}
	}

	if r.AppsecRuntime.DisabledOutOfBandRuleIds != nil {
		for _, id := range r.AppsecRuntime.DisabledOutOfBandRuleIds {
			r.AppsecOutbandEngine.GetRuleGroup().DeleteByID(id)
		}
	}

	r.logger.Tracef("Loaded inband rules: %+v", r.AppsecInbandEngine.GetRuleGroup().GetRules())
	r.logger.Tracef("Loaded outband rules: %+v", r.AppsecOutbandEngine.GetRuleGroup().GetRules())

	if err != nil {
		return fmt.Errorf("unable to initialize outband engine : %w", err)
	}

	return nil
}

func (r *AppsecRunner) processRequest(tx appsec.ExtendedTransaction, request *appsec.ParsedRequest) error {
	var in *corazatypes.Interruption
	var err error

	if request.Tx.IsRuleEngineOff() {
		r.logger.Debugf("rule engine is off, skipping")
		return nil
	}

	defer func() {
		request.Tx.ProcessLogging()
		//We don't close the transaction here, as it will reset coraza internal state and break variable tracking
	}()

	//pre eval (expr) rules
	err = r.AppsecRuntime.ProcessPreEvalRules(request)
	if err != nil {
		r.logger.Errorf("unable to process PreEval rules: %s", err)
		//FIXME: should we abort here ?
	}

	request.Tx.ProcessConnection(request.RemoteAddr, 0, "", 0)

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

	err = r.AppsecRuntime.ProcessPostEvalRules(request)
	if err != nil {
		r.logger.Errorf("unable to process PostEval rules: %s", err)
	}

	return nil
}

func (r *AppsecRunner) ProcessInBandRules(request *appsec.ParsedRequest) error {
	tx := appsec.NewExtendedTransaction(r.AppsecInbandEngine, request.UUID)
	r.AppsecRuntime.InBandTx = tx
	request.Tx = tx
	if len(r.AppsecRuntime.InBandRules) == 0 {
		return nil
	}
	err := r.processRequest(tx, request)
	return err
}

func (r *AppsecRunner) ProcessOutOfBandRules(request *appsec.ParsedRequest) error {
	tx := appsec.NewExtendedTransaction(r.AppsecOutbandEngine, request.UUID)
	r.AppsecRuntime.OutOfBandTx = tx
	request.Tx = tx
	if len(r.AppsecRuntime.OutOfBandRules) == 0 {
		return nil
	}
	err := r.processRequest(tx, request)
	return err
}

func (r *AppsecRunner) handleInBandInterrupt(request *appsec.ParsedRequest) {
	//create the associated event for crowdsec itself
	evt, err := EventFromRequest(request, r.Labels)
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
		r.AppsecRuntime.Response.InBandInterrupt = true
		r.AppsecRuntime.Response.HTTPResponseCode = r.AppsecRuntime.Config.BlockedHTTPCode
		r.AppsecRuntime.Response.Action = r.AppsecRuntime.DefaultRemediation

		if _, ok := r.AppsecRuntime.RemediationById[in.RuleID]; ok {
			r.AppsecRuntime.Response.Action = r.AppsecRuntime.RemediationById[in.RuleID]
		}

		for tag, remediation := range r.AppsecRuntime.RemediationByTag {
			if slices.Contains[[]string, string](in.Tags, tag) {
				r.AppsecRuntime.Response.Action = remediation
			}
		}

		err = r.AppsecRuntime.ProcessOnMatchRules(request, evt)
		if err != nil {
			r.logger.Errorf("unable to process OnMatch rules: %s", err)
			return
		}
		// Should the in band match trigger an event ?
		if r.AppsecRuntime.Response.SendEvent {
			r.outChan <- evt
		}

		// Should the in band match trigger an overflow ?
		if r.AppsecRuntime.Response.SendAlert {
			appsecOvlfw, err := AppsecEventGeneration(evt)
			if err != nil {
				r.logger.Errorf("unable to generate appsec event : %s", err)
				return
			}
			r.outChan <- *appsecOvlfw
		}
	}
}

func (r *AppsecRunner) handleOutBandInterrupt(request *appsec.ParsedRequest) {
	evt, err := EventFromRequest(request, r.Labels)
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
		r.AppsecRuntime.Response.OutOfBandInterrupt = true

		err = r.AppsecRuntime.ProcessOnMatchRules(request, evt)
		if err != nil {
			r.logger.Errorf("unable to process OnMatch rules: %s", err)
			return
		}
		// Should the match trigger an event ?
		if r.AppsecRuntime.Response.SendEvent {
			r.outChan <- evt
		}

		// Should the match trigger an overflow ?
		if r.AppsecRuntime.Response.SendAlert {
			appsecOvlfw, err := AppsecEventGeneration(evt)
			if err != nil {
				r.logger.Errorf("unable to generate appsec event : %s", err)
				return
			}
			r.outChan <- *appsecOvlfw
		}
	}
}

func (r *AppsecRunner) handleRequest(request *appsec.ParsedRequest) {
	r.AppsecRuntime.Logger = r.AppsecRuntime.Logger.WithField("request_uuid", request.UUID)
	logger := r.logger.WithField("request_uuid", request.UUID)
	logger.Debug("Request received in runner")
	r.AppsecRuntime.ClearResponse()

	request.IsInBand = true
	request.IsOutBand = false

	//to measure the time spent in the Application Security Engine for InBand rules
	startInBandParsing := time.Now()
	startGlobalParsing := time.Now()

	//inband appsec rules
	err := r.ProcessInBandRules(request)
	if err != nil {
		logger.Errorf("unable to process InBand rules: %s", err)
		return
	}

	// time spent to process in band rules
	inBandParsingElapsed := time.Since(startInBandParsing)
	AppsecInbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddrNormalized, "appsec_engine": request.AppsecEngine}).Observe(inBandParsingElapsed.Seconds())

	if request.Tx.IsInterrupted() {
		r.handleInBandInterrupt(request)
	}

	// send back the result to the HTTP handler for the InBand part
	request.ResponseChannel <- r.AppsecRuntime.Response

	//Now let's process the out of band rules

	request.IsInBand = false
	request.IsOutBand = true
	r.AppsecRuntime.Response.SendAlert = false
	r.AppsecRuntime.Response.SendEvent = true

	//FIXME: This is a bit of a hack to avoid confusion with the transaction if we do not have any inband rules.
	//We should probably have different transaction (or even different request object) for inband and out of band rules
	if len(r.AppsecRuntime.OutOfBandRules) > 0 {
		//to measure the time spent in the Application Security Engine for OutOfBand rules
		startOutOfBandParsing := time.Now()

		err = r.ProcessOutOfBandRules(request)
		if err != nil {
			logger.Errorf("unable to process OutOfBand rules: %s", err)
			return
		}

		// time spent to process out of band rules
		outOfBandParsingElapsed := time.Since(startOutOfBandParsing)
		AppsecOutbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddrNormalized, "appsec_engine": request.AppsecEngine}).Observe(outOfBandParsingElapsed.Seconds())
		if request.Tx.IsInterrupted() {
			r.handleOutBandInterrupt(request)
		}
	}
	// time spent to process inband AND out of band rules
	globalParsingElapsed := time.Since(startGlobalParsing)
	AppsecGlobalParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddrNormalized, "appsec_engine": request.AppsecEngine}).Observe(globalParsingElapsed.Seconds())

}

func (r *AppsecRunner) Run(t *tomb.Tomb) error {
	r.logger.Infof("Appsec Runner ready to process event")
	for {
		select {
		case <-t.Dying():
			r.logger.Infof("Appsec Runner is dying")
			return nil
		case request := <-r.inChan:
			r.handleRequest(&request)
		}
	}
}
