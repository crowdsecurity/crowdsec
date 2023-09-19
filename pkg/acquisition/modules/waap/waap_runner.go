package wafacquisition

import (
	"fmt"
	"os"
	"time"

	"github.com/crowdsecurity/coraza/v3"
	"github.com/crowdsecurity/coraza/v3/experimental"
	corazatypes "github.com/crowdsecurity/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
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

func (r *WaapRunner) Init() error {
	var err error
	fs := os.DirFS(csconfig.DataDir)

	inBandRules := ""
	outOfBandRules := ""

	for _, collection := range r.WaapRuntime.InBandRules {
		inBandRules += collection.String()
	}

	for _, collection := range r.WaapRuntime.OutOfBandRules {
		outOfBandRules += collection.String()
	}

	r.WaapInbandEngine, err = coraza.NewWAF(
		coraza.NewWAFConfig().WithDirectives(inBandRules).WithRootFS(fs),
	)

	if err != nil {
		return fmt.Errorf("unable to initialize inband engine : %w", err)
	}

	r.WaapOutbandEngine, err = coraza.NewWAF(
		coraza.NewWAFConfig().WithDirectives(outOfBandRules).WithRootFS(fs),
	)

	if err != nil {
		return fmt.Errorf("unable to initialize outband engine : %w", err)
	}

	return nil
}

func (r *WaapRunner) ProcessInBandRules(request *waf.ParsedRequest) error {
	var in *corazatypes.Interruption
	var err error

	tx := r.WaapInbandEngine.NewTransactionWithID(request.UUID)

	request.Tx = tx.(experimental.FullTransaction)

	if request.Tx.IsRuleEngineOff() {
		r.logger.Debugf("rule engine is off, skipping")
		return nil
	}

	defer func() {
		request.Tx.ProcessLogging()
		//We don't close the transaction here, as it will reset coraza internal state and break out of bands rules
	}()

	request.Tx.ProcessConnection(request.RemoteAddr, 0, "", 0)
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
		r.logger.Infof("inband rules matched for headers : %d", in.Action)
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
		r.logger.Infof("inband rules matched for body : %d", in.RuleID)
		return nil
	}

	return nil
}

func (r *WaapRunner) ProcessOutOfBandRules(request waf.ParsedRequest) (*corazatypes.Interruption, error) {

	return nil, nil
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

			WafReqCounter.With(prometheus.Labels{"source": request.RemoteAddr}).Inc()
			//to measure the time spent in the WAF
			startParsing := time.Now()

			//pre eval (expr) rules
			err := r.WaapRuntime.ProcessPreEvalRules(request)
			if err != nil {
				r.logger.Errorf("unable to process PreEval rules: %s", err)
				continue
			}
			log.Infof("now response is -> %s", r.WaapRuntime.Response.Action)
			//inband WAAP rules
			err = r.ProcessInBandRules(&request)
			if err != nil {
				r.logger.Errorf("unable to process InBand rules: %s", err)
				continue
			}

			if in := request.Tx.Interruption(); in != nil {
				r.logger.Debugf("inband rules matched : %d", in.RuleID)
				r.WaapRuntime.Response.InBandInterrupt = true
			}
			elapsed := time.Since(startParsing)
			WafInbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(elapsed.Seconds())

			//generate reponse for the remediation component, based on the WAAP config + inband rules evaluation
			//@tko : this should move in the WaapRuntimeConfig as it knows what to do with the interruption and the expected remediation
			err = r.WaapRuntime.ProcessOnMatchRules(request)
			if err != nil {
				r.logger.Errorf("unable to process OnMatch rules: %s", err)
				continue
			}

			// send back the result to the HTTP handler for the InBand part
			request.ResponseChannel <- r.WaapRuntime.Response

		}
	}
}
