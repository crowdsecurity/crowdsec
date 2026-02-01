package appsecacquisition

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/allowlists"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// that's the runtime structure of the Application security engine as seen from the acquis
type AppsecRunner struct {
	outChan                chan pipeline.Event
	inChan                 chan appsec.ParsedRequest
	UUID                   string
	AppsecRuntime          *appsec.AppsecRuntimeConfig //this holds the actual appsec runtime config, rules, remediations, hooks etc.
	AppsecInbandEngine     coraza.WAF
	AppsecOutbandEngine    coraza.WAF
	Labels                 map[string]string
	logger                 *log.Entry
	appsecAllowlistsClient *allowlists.AppsecAllowlist
}

func (*AppsecRunner) MergeDedupRules(collections []appsec.AppsecCollection, logger *log.Entry) string {
	var rulesArr []string
	dedupRules := make(map[string]struct{})
	discarded := 0

	for _, collection := range collections {
		// Dedup *our* rules
		for _, rule := range collection.Rules {
			if _, ok := dedupRules[rule]; ok {
				discarded++
				logger.Debugf("Discarding duplicate rule : %s", rule)
				continue
			}
			rulesArr = append(rulesArr, rule)
			dedupRules[rule] = struct{}{}
		}
		// Don't mess up with native modsec rules
		rulesArr = append(rulesArr, collection.NativeRules...)
	}
	if discarded > 0 {
		logger.Warningf("%d rules were discarded as they were duplicates", discarded)
	}

	return strings.Join(rulesArr, "\n")
}

func (r *AppsecRunner) Init(datadir string) error {
	var err error
	fs := os.DirFS(datadir)

	inBandLogger := r.logger.Dup().WithField("band", "inband")
	outBandLogger := r.logger.Dup().WithField("band", "outband")

	//While loading rules, we dedup rules based on their content, while keeping the order
	inBandRules := r.MergeDedupRules(r.AppsecRuntime.InBandRules, inBandLogger)
	outOfBandRules := r.MergeDedupRules(r.AppsecRuntime.OutOfBandRules, outBandLogger)

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
	if err != nil {
		return fmt.Errorf("unable to initialize outband engine : %w", err)
	}

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

	return nil
}

func (r *AppsecRunner) processRequest(state *appsec.AppsecRequestState, request *appsec.ParsedRequest) error {
	var in *corazatypes.Interruption
	var err error

	if state.Tx.IsRuleEngineOff() {
		r.logger.Debugf("rule engine is off, skipping")
		return nil
	}

	defer func() {
		state.Tx.ProcessLogging()
		//We don't close the transaction here, as it will reset coraza internal state and break variable tracking

		err := r.AppsecRuntime.ProcessPostEvalRules(state, request)
		if err != nil {
			r.logger.Errorf("unable to process PostEval rules: %s", err)
		}
	}()

	//pre eval (expr) rules
	err = r.AppsecRuntime.ProcessPreEvalRules(state, request)
	if err != nil {
		r.logger.Errorf("unable to process PreEval rules: %s", err)
		//FIXME: should we abort here ?
	}

	if state.DropInfo(request) != nil {
		r.logger.Debug("drop helper triggered during pre_eval, skipping WAF evaluation")
		return nil
	}

	state.Tx.ProcessConnection(request.ClientIP, 0, "", 0)

	for k, v := range request.Args {
		for _, vv := range v {
			state.Tx.AddGetRequestArgument(k, vv)
		}
	}

	state.Tx.ProcessURI(request.URI, request.Method, request.Proto)

	for k, vr := range request.Headers {
		for _, v := range vr {
			state.Tx.AddRequestHeader(k, v)
		}
	}

	if request.ClientHost != "" {
		state.Tx.AddRequestHeader("Host", request.ClientHost)
		state.Tx.SetServerName(request.ClientHost)
	}

	if request.TransferEncoding != nil {
		state.Tx.AddRequestHeader("Transfer-Encoding", request.TransferEncoding[0])
	}

	in = state.Tx.ProcessRequestHeaders()

	if in != nil {
		r.logger.Infof("inband rules matched for headers : %s", in.Action)
		return nil
	}

	if len(request.Body) > 0 {
		in, _, err = state.Tx.WriteRequestBody(request.Body)
		if err != nil {
			r.logger.Errorf("unable to write request body : %s", err)
			return err
		}
		if in != nil {
			return nil
		}
	}

	in, err = state.Tx.ProcessRequestBody()
	if err != nil {
		r.logger.Errorf("unable to process request body : %s", err)
		return err
	}

	if in != nil {
		r.logger.Debugf("rules matched for body : %d", in.RuleID)
	}

	return nil
}

func (r *AppsecRunner) ProcessInBandRules(state *appsec.AppsecRequestState, request *appsec.ParsedRequest) error {
	tx := appsec.NewExtendedTransaction(r.AppsecInbandEngine, request.UUID)
	state.Tx = tx
	// Even if we have no inband rules, we might have pre-eval rules to process
	if len(r.AppsecRuntime.InBandRules) == 0 && len(r.AppsecRuntime.CompiledPreEval) == 0 {
		return nil
	}
	err := r.processRequest(state, request)
	return err
}

func (r *AppsecRunner) ProcessOutOfBandRules(state *appsec.AppsecRequestState, request *appsec.ParsedRequest) error {
	tx := appsec.NewExtendedTransaction(r.AppsecOutbandEngine, request.UUID)
	state.Tx = tx
	if len(r.AppsecRuntime.OutOfBandRules) == 0 && len(r.AppsecRuntime.CompiledPreEval) == 0 {
		return nil
	}
	err := r.processRequest(state, request)
	return err
}

func (r *AppsecRunner) handleInBandInterrupt(state *appsec.AppsecRequestState, request *appsec.ParsedRequest) {

	if allowed, reason := r.appsecAllowlistsClient.IsAllowlisted(request.ClientIP); allowed {
		r.logger.Infof("%s is allowlisted by %s, skipping", request.ClientIP, reason)
		return
	}

	//create the associated event for crowdsec itself
	evt, err := EventFromRequest(request, r.Labels, state.Tx.ID())
	if err != nil {
		//let's not interrupt the pipeline for this
		r.logger.Errorf("unable to create event from request : %s", err)
	}
	r.AccumulateTxToEvent(&evt, state, request)

	interrupt := state.Tx.Interruption()
	dropInfo := state.InBandDrop

	if interrupt == nil && dropInfo == nil {
		return
	}

	if interrupt != nil {
		r.logger.Debugf("inband rules matched : %d", interrupt.RuleID)
	} else if dropInfo != nil {
		r.logger.Debugf("inband drop helper triggered: %s", dropInfo.Reason)
		interrupt = dropInfo.Interruption
	}

	state.Response.InBandInterrupt = true
	state.Response.BouncerHTTPResponseCode = r.AppsecRuntime.Config.BouncerBlockedHTTPCode
	state.Response.UserHTTPResponseCode = r.AppsecRuntime.Config.UserBlockedHTTPCode
	state.Response.Action = r.AppsecRuntime.DefaultRemediation
	state.ApplyPendingResponse()

	if _, ok := r.AppsecRuntime.RemediationById[interrupt.RuleID]; ok {
		state.Response.Action = r.AppsecRuntime.RemediationById[interrupt.RuleID]
	}

	for tag, remediation := range r.AppsecRuntime.RemediationByTag {
		if slices.Contains(interrupt.Tags, tag) {
			state.Response.Action = remediation
		}
	}

	if dropInfo != nil && dropInfo.Reason != "" {
		evt.Meta["appsec_drop_reason"] = dropInfo.Reason
	}

	err = r.AppsecRuntime.ProcessOnMatchRules(state, request, evt)
	if err != nil {
		r.logger.Errorf("unable to process OnMatch rules: %s", err)
		return
	}

	// Should the in band match trigger an overflow ?
	if state.Response.SendAlert {
		appsecOvlfw, err := AppsecEventGeneration(evt, request.HTTPRequest)
		if err != nil {
			r.logger.Errorf("unable to generate appsec event : %s", err)
			return
		}
		if appsecOvlfw != nil {
			r.outChan <- *appsecOvlfw
		}
	}
	// Should the in band match trigger an event ?
	if state.Response.SendEvent {
		r.outChan <- evt
	}
}

func (r *AppsecRunner) handleOutBandInterrupt(state *appsec.AppsecRequestState, request *appsec.ParsedRequest) {

	if allowed, reason := r.appsecAllowlistsClient.IsAllowlisted(request.ClientIP); allowed {
		r.logger.Infof("%s is allowlisted by %s, skipping", request.ClientIP, reason)
		return
	}

	evt, err := EventFromRequest(request, r.Labels, state.Tx.ID())
	if err != nil {
		//let's not interrupt the pipeline for this
		r.logger.Errorf("unable to create event from request : %s", err)
	}
	r.AccumulateTxToEvent(&evt, state, request)
	interrupt := state.Tx.Interruption()
	dropInfo := state.OutOfBandDrop
	if interrupt == nil && dropInfo == nil {
		return
	}
	if interrupt == nil && dropInfo != nil {
		interrupt = dropInfo.Interruption
	}

	if dropInfo != nil {
		r.logger.Debugf("out-of-band drop helper triggered: %s", dropInfo.Reason)
	} else {
		r.logger.Debugf("outband rules matched : %d", interrupt.RuleID)
	}

	state.Response.OutOfBandInterrupt = true
	state.ApplyPendingResponse()

	if dropInfo != nil && dropInfo.Reason != "" {
		if evt.Meta == nil {
			evt.Meta = map[string]string{}
		}
		evt.Meta["appsec_drop_reason"] = dropInfo.Reason
	}

	err = r.AppsecRuntime.ProcessOnMatchRules(state, request, evt)
	if err != nil {
		r.logger.Errorf("unable to process OnMatch rules: %s", err)
		return
	}

	// The alert needs to be sent first:
	// The event and the alert share the same internal map (parsed, meta, ...)
	// The event can be modified by the parsers, which might cause a concurrent map read/write
	// Should the match trigger an overflow ?
	if state.Response.SendAlert {
		appsecOvlfw, err := AppsecEventGeneration(evt, request.HTTPRequest)
		if err != nil {
			r.logger.Errorf("unable to generate appsec event : %s", err)
			return
		}
		if appsecOvlfw != nil {
			r.outChan <- *appsecOvlfw
		}
	}

	// Should the match trigger an event ?
	if state.Response.SendEvent {
		r.outChan <- evt
	}
}

func (r *AppsecRunner) handleRequest(request *appsec.ParsedRequest) {
	state := r.AppsecRuntime.NewRequestState()
	stateLogger := r.AppsecRuntime.Logger.WithField("request_uuid", request.UUID)
	r.AppsecRuntime.Logger = stateLogger
	logger := r.logger.WithField("request_uuid", request.UUID)
	logger.Debug("Request received in runner")
	r.AppsecRuntime.ClearResponse(&state)

	request.IsInBand = true
	request.IsOutBand = false

	//to measure the time spent in the Application Security Engine for InBand rules
	startInBandParsing := time.Now()
	startGlobalParsing := time.Now()

	state.CurrentPhase = appsec.PhaseInBand

	//inband appsec rules
	err := r.ProcessInBandRules(&state, request)
	if err != nil {
		logger.Errorf("unable to process InBand rules: %s", err)
		err = state.Tx.Close()
		if err != nil {
			logger.Errorf("unable to close inband transaction: %s", err)
		}
		return
	}

	// time spent to process in band rules
	inBandParsingElapsed := time.Since(startInBandParsing)
	metrics.AppsecInbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddrNormalized, "appsec_engine": request.AppsecEngine}).Observe(inBandParsingElapsed.Seconds())

	if state.Tx.IsInterrupted() || state.InBandDrop != nil {
		r.handleInBandInterrupt(&state, request)
	}

	err = state.Tx.Close()
	if err != nil {
		r.logger.Errorf("unable to close inband transaction: %s", err)
	}

	// send back the result to the HTTP handler for the InBand part
	request.ResponseChannel <- state.Response

	// TODO: what should we do with challenge remediation for OOB matches ?
	// (captcha has no special treatment, but is also useless for OOB)

	//Now let's process the out of band rules

	request.IsInBand = false
	request.IsOutBand = true
	state.Response.SendAlert = false
	state.Response.SendEvent = true
	state.CurrentPhase = appsec.PhaseOutOfBand

	//FIXME: This is a bit of a hack to avoid confusion with the transaction if we do not have any inband rules.
	//We should probably have different transaction (or even different request object) for inband and out of band rules
	if len(r.AppsecRuntime.OutOfBandRules) > 0 {
		//to measure the time spent in the Application Security Engine for OutOfBand rules
		startOutOfBandParsing := time.Now()

		err = r.ProcessOutOfBandRules(&state, request)
		if err != nil {
			logger.Errorf("unable to process OutOfBand rules: %s", err)
			err = state.Tx.Close()
			if err != nil {
				logger.Errorf("unable to close outband transaction: %s", err)
			}
			return
		}

		// time spent to process out of band rules
		outOfBandParsingElapsed := time.Since(startOutOfBandParsing)
		metrics.AppsecOutbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddrNormalized, "appsec_engine": request.AppsecEngine}).Observe(outOfBandParsingElapsed.Seconds())
		if state.Tx.IsInterrupted() || state.OutOfBandDrop != nil {
			r.handleOutBandInterrupt(&state, request)
		}
	}
	err = state.Tx.Close()
	if err != nil {
		r.logger.Errorf("unable to close outband transaction: %s", err)
	}
	// time spent to process inband AND out of band rules
	globalParsingElapsed := time.Since(startGlobalParsing)
	metrics.AppsecGlobalParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddrNormalized, "appsec_engine": request.AppsecEngine}).Observe(globalParsingElapsed.Seconds())
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
