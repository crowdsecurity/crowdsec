package wafacquisition

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
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

var wafParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the WAF.",
		Name:    "cs_waf_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"source"},
)

var wafReqCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_waf_reqs_total",
		Help: "Total events processed by the WAF.",
	},
	[]string{"source"},
)

var wafRuleHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_waf_rule_hits",
		Help: "Count of triggered rule, by rule_id and type (inband/outofband).",
	},
	[]string{"rule_id", "type"},
)

const (
	InBand    = "inband"
	OutOfBand = "outofband"
)

type WafRunner struct {
	outChan      chan types.Event
	inChan       chan ParsedRequest
	inBandWaf    coraza.WAF
	outOfBandWaf coraza.WAF
	UUID         string
}

type WafSource struct {
	config  WafSourceConfig
	logger  *log.Entry
	mux     *http.ServeMux
	server  *http.Server
	addr    string
	outChan chan types.Event
	InChan  chan ParsedRequest

	inBandWaf    coraza.WAF
	outOfBandWaf coraza.WAF

	WafRunners []WafRunner
}

type ParsedRequest struct {
	RemoteAddr       string
	Host             string
	ClientIP         string
	URI              string
	ClientHost       string
	Headers          http.Header
	URL              *url.URL
	Method           string
	Proto            string
	Body             []byte
	TransferEncoding []string
	UUID             string
	Tx               corazatypes.Transaction
	ResponseChannel  chan ResponseRequest
}

type ResponseRequest struct {
	ResponseChannel chan ResponseRequest
	UUID            string
	Tx              corazatypes.Transaction
	Interruption    *corazatypes.Interruption
	Err             error
}

type WafSourceConfig struct {
	ListenAddr                        string `yaml:"listen_addr"`
	ListenPort                        int    `yaml:"listen_port"`
	Path                              string `yaml:"path"`
	WafRoutines                       int    `yaml:"waf_routines"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

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
	msg := error.ErrorLog(0)
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

	w.InChan = make(chan ParsedRequest)
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

		runner := WafRunner{
			outOfBandWaf: outofbandwaf,
			inBandWaf:    inbandwaf,
			inChan:       w.InChan,
			UUID:         uuid.New().String(),
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

func NewParsedRequestFromRequest(r *http.Request) (ParsedRequest, error) {
	var body []byte
	var err error

	if r.Body != nil {
		body = make([]byte, 0)
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return ParsedRequest{}, fmt.Errorf("unable to read body: %s", err)
		}
	}

	// the real source of the request is set in 'x-client-ip'
	clientIP := r.Header.Get("X-Client-Ip")
	// the real target Host of the request is set in 'x-client-host'
	clientHost := r.Header.Get("X-Client-Host")
	// the real URI of the request is set in 'x-client-uri'
	clientURI := r.Header.Get("X-Client-Uri")

	// delete those headers before coraza process the request
	delete(r.Header, "x-client-ip")
	delete(r.Header, "x-client-host")
	delete(r.Header, "x-client-uri")

	return ParsedRequest{
		RemoteAddr:       r.RemoteAddr,
		UUID:             uuid.New().String(),
		ClientHost:       clientHost,
		ClientIP:         clientIP,
		URI:              clientURI,
		Host:             r.Host,
		Headers:          r.Header,
		URL:              r.URL,
		Method:           r.Method,
		Proto:            r.Proto,
		Body:             body,
		TransferEncoding: r.TransferEncoding,
		ResponseChannel:  make(chan ResponseRequest),
	}, nil
}

func processReqWithEngine(waf coraza.WAF, r ParsedRequest, uuid string, wafType string) (*corazatypes.Interruption, corazatypes.Transaction, error) {
	var in *corazatypes.Interruption
	tx := waf.NewTransactionWithID(uuid)

	if tx.IsRuleEngineOff() {
		log.Printf("engine is off")
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

	tx.ProcessConnection(r.ClientIP, 0, "", 0)

	//tx.ProcessURI(r.URL.String(), r.Method, r.Proto) //FIXME: get it from the headers
	tx.ProcessURI(r.URI, r.Method, r.Proto) //FIXME: get it from the headers

	for k, vr := range r.Headers {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	if r.ClientHost != "" {
		tx.AddRequestHeader("Host", r.ClientHost)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(r.ClientHost)
	}

	if r.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", r.TransferEncoding[0])
	}

	in = tx.ProcessRequestHeaders()
	//spew.Dump(in)
	//spew.Dump(tx.MatchedRules())

	/*for _, rule := range tx.MatchedRules() {
		spew.Dump(rule.Rule())
	}*/

	//if we're inband, we should stop here, but for outofband go to the end
	if in != nil && wafType == InBand {
		return in, tx, nil
	}

	ct := r.Headers.Get("content-type")
	if r.Body != nil && len(r.Body) != 0 {
		it, _, err := tx.WriteRequestBody(r.Body)
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
			log.Infof("Waf Runner is dying")
			return nil
		case request := <-r.inChan:
			wafReqCounter.With(prometheus.Labels{"source": request.RemoteAddr}).Inc()
			//measure the time spent in the WAF
			startParsing := time.Now()
			in, tx, err := processReqWithEngine(r.inBandWaf, request, request.UUID, InBand)
			response := ResponseRequest{
				Tx:           tx,
				Interruption: in,
				Err:          err,
				UUID:         request.UUID,
			}
			// send back the result to the HTTP handler for the InBand part
			request.ResponseChannel <- response
			if in != nil {
				request.Tx = tx
				// Generate the events for InBand channel
				events, err := TxToEvents(request, InBand)
				if err != nil {
					log.Errorf("Cannot convert transaction to events : %s", err)
					continue
				}

				for _, evt := range events {
					r.outChan <- evt
				}
			}

			// Process outBand
			in, tx, err = processReqWithEngine(r.outOfBandWaf, request, request.UUID, OutOfBand)
			if err != nil { //things went south
				log.Errorf("Error while processing request : %s", err)
				continue
			}
			request.Tx = tx
			if tx != nil && len(tx.MatchedRules()) > 0 {
				events, err := TxToEvents(request, OutOfBand)
				log.Infof("Request triggered by WAF, %d events to send", len(events))
				for _, evt := range events {
					r.outChan <- evt
				}
				if err != nil {
					log.Errorf("Cannot convert transaction to events : %s", err)
					continue
				}
			}
			//measure the full time spent in the WAF
			elapsed := time.Since(startParsing)
			wafParsingHistogram.With(prometheus.Labels{"source": request.RemoteAddr}).Observe(elapsed.Seconds())
		}
	}
}

func (w *WafSource) wafHandler(rw http.ResponseWriter, r *http.Request) {
	// parse the request only once
	parsedRequest, err := NewParsedRequestFromRequest(r)
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
		return
	}

	rw.WriteHeader(http.StatusOK)

	return
}
