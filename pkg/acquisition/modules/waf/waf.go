package wafacquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/coraza/v3"
	"github.com/crowdsecurity/coraza/v3/experimental"
	corazatypes "github.com/crowdsecurity/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/crowdsecurity/go-cs-lib/pkg/trace"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

const (
	InBand    = "inband"
	OutOfBand = "outofband"
)

type WafRunner struct {
	outChan          chan types.Event
	inChan           chan waf.ParsedRequest
	inBandWaf        coraza.WAF
	outOfBandWaf     coraza.WAF
	UUID             string
	RulesCollections []*waf.WafRulesCollection
	logger           *log.Entry
}

type WafSourceConfig struct {
	ListenAddr                        string `yaml:"listen_addr"`
	ListenPort                        int    `yaml:"listen_port"`
	Path                              string `yaml:"path"`
	WafRoutines                       int    `yaml:"waf_routines"`
	Debug                             bool   `yaml:"debug"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type WafSource struct {
	config  WafSourceConfig
	logger  *log.Entry
	mux     *http.ServeMux
	server  *http.Server
	addr    string
	outChan chan types.Event
	InChan  chan waf.ParsedRequest

	inBandWaf        coraza.WAF
	outOfBandWaf     coraza.WAF
	RulesCollections []*waf.WafRulesCollection

	WafRunners []WafRunner
}

var WafGlobalParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the WAF.",
		Name:    "cs_waf_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"source"},
)

var WafInbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the inband WAF.",
		Name:    "cs_waf_inband_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"source"},
)

var WafOutbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the WAF.",
		Name:    "cs_waf_outband_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"source"},
)

var WafReqCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_waf_reqs_total",
		Help: "Total events processed by the WAF.",
	},
	[]string{"source"},
)

var WafRuleHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_waf_rule_hits",
		Help: "Count of triggered rule, by rule_id and type (inband/outofband).",
	},
	[]string{"rule_id", "type"},
)

func (w *WafSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (w *WafSource) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func (w *WafSource) UnmarshalConfig(yamlConfig []byte) error {
	wafConfig := WafSourceConfig{}
	err := yaml.UnmarshalStrict(yamlConfig, &wafConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse waf configuration")
	}

	w.config = wafConfig

	if w.config.ListenAddr == "" {
		return fmt.Errorf("listen_addr cannot be empty")
	}

	if w.config.ListenPort == 0 {
		return fmt.Errorf("listen_port cannot be empty")
	}

	//FIXME: is that really needed ?
	if w.config.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	if w.config.Path[0] != '/' {
		w.config.Path = "/" + w.config.Path
	}

	if w.config.Mode == "" {
		w.config.Mode = configuration.TAIL_MODE
	}

	return nil
}

func logError(error corazatypes.MatchedRule) {
	msg := error.ErrorLog()
	log.Infof("[logError][%s]  %s", error.Rule().Severity(), msg)
}

func (w *WafSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	err := w.UnmarshalConfig(yamlConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse waf configuration")
	}

	w.logger = logger

	w.logger.Tracef("WAF configuration: %+v", w.config)

	w.addr = fmt.Sprintf("%s:%d", w.config.ListenAddr, w.config.ListenPort)

	w.mux = http.NewServeMux()

	w.server = &http.Server{
		Addr:    w.addr,
		Handler: w.mux,
	}

	ruleLoader := waf.NewWafRuleLoader()

	rulesCollections, err := ruleLoader.LoadWafRules()
	if err != nil {
		return fmt.Errorf("cannot load WAF rules: %w", err)
	}

	w.RulesCollections = rulesCollections

	var inBandRules string
	var outOfBandRules string

	//spew.Dump(rulesCollections)

	for _, collection := range rulesCollections {
		if !collection.OutOfBand {
			inBandRules += collection.String() + "\n"
		} else {
			outOfBandRules += collection.String() + "\n"
		}
	}

	w.logger.Infof("Loading %d in-band rules", len(strings.Split(inBandRules, "\n")))

	//w.logger.Infof("Loading rules %+v", inBandRules)

	fs := os.DirFS(ruleLoader.Datadir)
	// always have at least one waf routine
	if w.config.WafRoutines == 0 {
		w.config.WafRoutines = 1
	}

	w.InChan = make(chan waf.ParsedRequest)
	w.WafRunners = make([]WafRunner, w.config.WafRoutines)
	for nbRoutine := 0; nbRoutine < w.config.WafRoutines; nbRoutine++ {
		w.logger.Infof("Loading %d in-band rules", len(strings.Split(inBandRules, "\n")))

		//in-band waf : kill on sight
		inbandwaf, err := coraza.NewWAF(
			coraza.NewWAFConfig().
				//WithErrorCallback(logError).
				WithDirectives(inBandRules).WithRootFS(fs),
		)

		if err != nil {
			return errors.Wrap(err, "Cannot create WAF")
		}
		w.logger.Infof("Loading %d out-of-band rules", len(strings.Split(outOfBandRules, "\n")))
		//out-of-band waf : log only
		outofbandwaf, err := coraza.NewWAF(
			coraza.NewWAFConfig().
				//WithErrorCallback(logError).
				WithDirectives(outOfBandRules).WithRootFS(fs),
		)

		if err != nil {
			return errors.Wrap(err, "Cannot create WAF")
		}
		wafUUID := uuid.New().String()
		wafLogger := &log.Entry{}
		if w.config.Debug {
			var clog = log.New()
			if err := types.ConfigureLogger(clog); err != nil {
				log.Fatalf("While creating bucket-specific logger : %s", err)
			}
			clog.SetLevel(log.DebugLevel)
			wafLogger = clog.WithFields(log.Fields{
				"uuid": wafUUID,
			})
		} else {
			wafLogger = log.WithFields(log.Fields{
				"uuid": wafUUID,
			})
		}

		runner := WafRunner{
			outOfBandWaf:     outofbandwaf,
			inBandWaf:        inbandwaf,
			inChan:           w.InChan,
			UUID:             wafUUID,
			RulesCollections: rulesCollections,
			logger:           wafLogger,
		}
		w.WafRunners[nbRoutine] = runner
	}

	w.logger.Infof("Loading %d out-of-band rules", len(strings.Split(outOfBandRules, "\n")))
	if err != nil {
		return errors.Wrap(err, "Cannot create WAF")
	}

	//We don´t use the wrapper provided by coraza because we want to fully control what happens when a rule match to send the information in crowdsec
	w.mux.HandleFunc(w.config.Path, w.wafHandler)

	return nil
}

func (w *WafSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return fmt.Errorf("WAF datasource does not support command line acquisition")
}

func (w *WafSource) GetMode() string {
	return w.config.Mode
}

func (w *WafSource) GetName() string {
	return "waf"
}

func (w *WafSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("WAF datasource does not support command line acquisition")
}

func (w *WafSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	w.outChan = out
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/waf/live")

		w.logger.Infof("%d waf runner to start", len(w.WafRunners))
		for _, runner := range w.WafRunners {
			w.logger.Infof("Running waf runner: %s", runner.UUID)
			runner.outChan = out
			t.Go(func() error {
				return runner.Run(t)
			})
		}

		w.logger.Infof("Starting WAF server on %s:%d%s", w.config.ListenAddr, w.config.ListenPort, w.config.Path)
		t.Go(func() error {
			err := w.server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				return errors.Wrap(err, "WAF server failed")
			}
			return nil
		})
		<-t.Dying()
		w.logger.Infof("Stopping WAF server on %s:%d%s", w.config.ListenAddr, w.config.ListenPort, w.config.Path)
		w.server.Shutdown(context.TODO())
		return nil
	})
	return nil
}

func (w *WafSource) CanRun() error {
	return nil
}

func (w *WafSource) GetUuid() string {
	return w.config.UniqueId
}

func (w *WafSource) Dump() interface{} {
	return w
}

func (r *WafRunner) processReqWithEngine(tx experimental.FullTransaction, parsedRequest waf.ParsedRequest, wafType string) (*corazatypes.Interruption, experimental.FullTransaction, error) {
	var in *corazatypes.Interruption
	if tx.IsRuleEngineOff() {
		r.logger.Printf("engine is off")
		return nil, nil, nil
	}

	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	//this method is not exported by coraza, so we have to do it ourselves.
	//ideally, this would be dealt with by expr code, and we provide helpers to manipulate the transaction object?\
	//var txx experimental.FullTransaction

	//txx := experimental.ToFullInterface(tx)
	//txx = tx.(experimental.FullTransaction)
	//txx.RemoveRuleByID(1)
	tx.ProcessConnection(parsedRequest.ClientIP, 0, "", 0)

	//tx.ProcessURI(parsedRequest.URL.String(), parsedRequest.Method, parsedRequest.Proto) //FIXME: get it from the headers
	tx.ProcessURI(parsedRequest.URI, parsedRequest.Method, parsedRequest.Proto) //FIXME: get it from the headers

	for k, vr := range parsedRequest.Headers {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	if parsedRequest.ClientHost != "" {
		tx.AddRequestHeader("Host", parsedRequest.ClientHost)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(parsedRequest.ClientHost)
	}

	if parsedRequest.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", parsedRequest.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()

	//spew.Dump(in)
	//spew.Dump(tx.MatchedRules())

	for _, rule := range tx.MatchedRules() {
		r.logger.Infof("Rule %d disruptive: %t", rule.Rule().ID(), rule.Disruptive())
		if rule.Message() == "" {
			continue
		}
	}

	//if we're inband, we should stop here, but for outofband go to the end
	if in != nil && wafType == InBand {
		return in, tx, nil
	}

	ct := parsedRequest.Headers.Get("content-type")
	if parsedRequest.Body != nil && len(parsedRequest.Body) != 0 {
		it, _, err := tx.WriteRequestBody(parsedRequest.Body)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Cannot read request body")
		}

		if it != nil {
			return it, nil, nil
		}
		// from https://github.com/corazawaf/coraza/blob/main/internal/corazawaf/transaction.go#L419
		// urlencoded cannot end with CRLF
		if ct != "application/x-www-form-urlencoded" {
			it, _, err := tx.WriteRequestBody([]byte{'\r', '\n'})
			if err != nil {
				return nil, nil, fmt.Errorf("cannot write to request body to buffer: %s", err.Error())
			}

			if it != nil {
				return it, nil, nil
			}
		}
	}
	in, err := tx.ProcessRequestBody()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Cannot process request body")
	}
	if in != nil && wafType == InBand {
		return in, tx, nil
	}

	return nil, tx, nil
}

func (r *WafRunner) Run(t *tomb.Tomb) error {
	for {
		select {
		case <-t.Dying():
			r.logger.Infof("Waf Runner is dying")
			return nil
		case request := <-r.inChan:
			var evt *types.Event
			WafReqCounter.With(prometheus.Labels{"source": request.RemoteAddr}).Inc()
			//measure the time spent in the WAF
			startParsing := time.Now()
			inBoundTx := r.inBandWaf.NewTransactionWithID(request.UUID)
			expTx := inBoundTx.(experimental.FullTransaction)
			// we use this internal transaction for the expr helpers
			tx := waf.NewTransaction(expTx)

			//Run the pre_eval hooks
			for _, rules := range r.RulesCollections {
				if len(rules.CompiledPreEval) == 0 {
					continue
				}
				for _, compiledHook := range rules.CompiledPreEval {
					if compiledHook.Filter != nil {
						res, err := expr.Run(compiledHook.Filter, map[string]interface{}{
							"rules": rules,
							"req":   request,
						})
						if err != nil {
							log.Errorf("unable to run PreEval filter: %s", err)
							continue
						}

						switch t := res.(type) {
						case bool:
							if t == false {
								log.Infof("filter didnt match")
								continue
							}
						default:
							log.Errorf("Filter must return a boolean, can't filter")
							continue
						}
					}
					// here means there is no filter or the filter matched
					for _, applyExpr := range compiledHook.Apply {
						_, err := expr.Run(applyExpr, map[string]interface{}{
							"rules":          rules,
							"req":            request,
							"RemoveRuleByID": tx.RemoveRuleByIDWithError,
						})
						if err != nil {
							log.Errorf("unable to apply filter: %s", err)
							continue
						}
					}
				}
			}

			in, expTx, err := r.processReqWithEngine(expTx, request, InBand)
			request.Tx = expTx
			//log.Infof("-> %s", spew.Sdump(in))

			response := waf.NewResponseRequest(expTx, in, request.UUID, err)

			// run the on_match hooks
			for _, rules := range r.RulesCollections {
				if len(rules.CompiledOnMatch) == 0 {
					continue
				}
				for _, compiledHook := range rules.CompiledOnMatch {
					if compiledHook.Filter != nil {
						res, err := expr.Run(compiledHook.Filter, map[string]interface{}{
							"rules": rules,
							"req":   request,
						})
						if err != nil {
							r.logger.Errorf("unable to run PreEval filter: %s", err)
							continue
						}

						switch t := res.(type) {
						case bool:
							if t == false {
								continue
							}
						default:
							r.logger.Errorf("Filter must return a boolean, can't filter")
							continue
						}
					}
					// here means there is no filter or the filter matched
					for _, applyExpr := range compiledHook.Apply {
						_, err := expr.Run(applyExpr, map[string]interface{}{
							"rules":              rules,
							"req":                request,
							"RemoveRuleByID":     tx.RemoveRuleByIDWithError,
							"SetRemediation":     response.SetRemediation,
							"SetRemediationByID": response.SetRemediationByID,
							"CancelEvent":        response.CancelEvent,
						})
						if err != nil {
							r.logger.Errorf("unable to apply filter: %s", err)
							continue
						}
					}
				}
			}
			//measure the full time spent in the WAF
			elapsed := time.Since(startParsing)
			WafInbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(elapsed.Seconds())
			// send back the result to the HTTP handler for the InBand part
			request.ResponseChannel <- response
			if in != nil && response.SendEvents {
				evt = &types.Event{}
				*evt, err = EventFromRequest(request)
				if err != nil {
					return fmt.Errorf("cannot create event from waap context : %w", err)
				}
				err = r.AccumulateTxToEvent(expTx, InBand, evt)
				if err != nil {
					return fmt.Errorf("cannot convert transaction to event : %w", err)
				}
				LogWaapEvent(evt)
				r.outChan <- *evt
			}

			outBandStart := time.Now()
			// Process outBand
			outBandTx := r.outOfBandWaf.NewTransactionWithID(request.UUID)
			expTx = outBandTx.(experimental.FullTransaction)
			in, expTx, err = r.processReqWithEngine(expTx, request, OutOfBand)
			if err != nil { //things went south
				r.logger.Errorf("Error while processing request : %s", err)
				continue
			}
			request.Tx = expTx
			if expTx != nil && len(expTx.MatchedRules()) > 0 {
				//if event was not instantiated after inband processing, do it now
				if evt == nil {
					*evt, err = EventFromRequest(request)
					if err != nil {
						return fmt.Errorf("cannot create event from waap context : %w", err)
					}
				}

				err = r.AccumulateTxToEvent(expTx, InBand, evt)
				if err != nil {
					return fmt.Errorf("cannot convert transaction to event : %w", err)
				}
				LogWaapEvent(evt)
				r.outChan <- *evt

			}
			//measure the full time spent in the WAF
			totalElapsed := time.Since(startParsing)
			WafGlobalParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(totalElapsed.Seconds())
			elapsed = time.Since(outBandStart)
			WafOutbandParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(elapsed.Seconds())
		}
	}
}

type BodyResponse struct {
	Action string `json:"action"`
}

func (w *WafSource) wafHandler(rw http.ResponseWriter, r *http.Request) {
	// parse the request only once
	parsedRequest, err := waf.NewParsedRequestFromRequest(r)
	if err != nil {
		log.Errorf("%s", err)
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	w.InChan <- parsedRequest

	message := <-parsedRequest.ResponseChannel

	if message.Err != nil {
		log.Errorf("Error while processing InBAND: %s", err)
		rw.WriteHeader(http.StatusOK)
		return
	}

	if message.Interruption != nil {
		rw.WriteHeader(http.StatusForbidden)
		action := message.Interruption.Action
		if action == "deny" { // bouncers understand "ban" and not "deny"
			action = "ban"
		}
		body, err := json.Marshal(BodyResponse{Action: action})
		if err != nil {
			log.Errorf("unable to build response: %s", err)
		} else {
			rw.Write(body)
		}
		return
	}

	rw.WriteHeader(http.StatusOK)
	body, err := json.Marshal(BodyResponse{Action: "allow"})
	if err != nil {
		log.Errorf("unable to build response: %s", err)
	} else {
		rw.Write(body)
	}

	return
}
