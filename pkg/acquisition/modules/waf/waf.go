package wafacquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type WafSource struct {
	config       WafSourceConfig
	logger       *log.Entry
	mux          *http.ServeMux
	server       *http.Server
	addr         string
	outChan      chan types.Event
	inBandWaf    coraza.WAF
	outOfBandWaf coraza.WAF
}

type WafSourceConfig struct {
	ListenAddr                        string `yaml:"listen_addr"`
	ListenPort                        int    `yaml:"listen_port"`
	Path                              string `yaml:"path"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

/*
type DataSource interface {
	GetMetrics() []prometheus.Collector                                 // Returns pointers to metrics that are managed by the module
	GetAggregMetrics() []prometheus.Collector                           // Returns pointers to metrics that are managed by the module (aggregated mode, limits cardinality)
	UnmarshalConfig([]byte) error                                       // Decode and pre-validate the YAML datasource - anything that can be checked before runtime
	Configure([]byte, *log.Entry) error                                 // Complete the YAML datasource configuration and perform runtime checks.
	ConfigureByDSN(string, map[string]string, *log.Entry, string) error // Configure the datasource
	GetMode() string                                                    // Get the mode (TAIL, CAT or SERVER)
	GetName() string                                                    // Get the name of the module
	OneShotAcquisition(chan types.Event, *tomb.Tomb) error              // Start one shot acquisition(eg, cat a file)
	StreamingAcquisition(chan types.Event, *tomb.Tomb) error            // Start live acquisition (eg, tail a file)
	CanRun() error                                                      // Whether the datasource can run or not (eg, journalctl on BSD is a non-sense)
	GetUuid() string                                                    // Get the unique identifier of the datasource
	Dump() interface{}
}
*/

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

	//in-band waf : kill on sight
	inbandwaf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectivesFromFile("coraza_inband.conf"),
	)

	if err != nil {
		return errors.Wrap(err, "Cannot create WAF")
	}
	w.inBandWaf = inbandwaf

	//out-of-band waf : log only
	outofbandwaf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectivesFromFile("coraza_outofband.conf"),
	)
	if err != nil {
		return errors.Wrap(err, "Cannot create WAF")
	}
	w.outOfBandWaf = outofbandwaf

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
		defer types.CatchPanic("crowdsec/acquis/waf/live")
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

func processReqWithEngine(waf coraza.WAF, r *http.Request, uuid string) (*corazatypes.Interruption, corazatypes.Transaction, error) {
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
	var txx experimental.FullTransaction

	//txx := experimental.ToFullInterface(tx)
	txx = tx.(experimental.FullTransaction)
	txx.RemoveRuleByID(1)

	tx.ProcessConnection(r.RemoteAddr, 0, "", 0)

	tx.ProcessURI(r.URL.String(), r.Method, r.Proto) //FIXME: get it from the headers

	for k, vr := range r.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(r.Host)
	}

	if r.TransferEncoding != nil {
		tx.AddRequestHeader("Transfer-Encoding", r.TransferEncoding[0])
	}

	in := tx.ProcessRequestHeaders()
	if in != nil {
		log.Printf("headerss")
		return in, tx, nil
	}

	if tx.IsRequestBodyAccessible() {
		if r.Body != nil && r.Body != http.NoBody {
			_, _, err := tx.ReadRequestBodyFrom(r.Body)
			if err != nil {
				return nil, nil, errors.Wrap(err, "Cannot read request body")
			}
			bodyReader, err := tx.RequestBodyReader()
			if err != nil {
				return nil, nil, errors.Wrap(err, "Cannot read request body")

			}
			body := io.MultiReader(bodyReader, r.Body)
			r.Body = ioutil.NopCloser(body)
			in, err = tx.ProcessRequestBody()
			if err != nil {
				return nil, nil, errors.Wrap(err, "Cannot process request body")

			}
			if in != nil {
				log.Printf("exception while processing body")
				return in, tx, nil
			}
		}
	}
	log.Printf("done")

	return nil, nil, nil
}

func (w *WafSource) TxToEvents(tx corazatypes.Transaction, r *http.Request) ([]types.Event, error) {
	evts := []types.Event{}
	if tx == nil {
		return nil, fmt.Errorf("tx is nil")
	}
	for idx, rule := range tx.MatchedRules() {
		log.Printf("rule %d", idx)
		evt, err := w.RuleMatchToEvent(rule, tx, r)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot convert rule match to event")
		}
		evts = append(evts, evt)
	}

	return evts, nil
}

// Transforms a coraza interruption to a crowdsec event
func (w *WafSource) RuleMatchToEvent(rule corazatypes.MatchedRule, tx corazatypes.Transaction, r *http.Request) (types.Event, error) {
	evt := types.Event{}
	//we might want to change this based on in-band vs out-of-band ?
	evt.Type = types.LOG
	evt.ExpectMode = types.LIVE
	//def needs fixing
	evt.Stage = "s00-raw"
	evt.Process = true

	//we build a big-ass object that is going to be marshaled in line.raw and unmarshaled later.
	//why ? because it's more consistent with the other data-sources etc. and it provides users with flexibility to alter our parsers
	CorazaEvent := map[string]interface{}{
		//core rule info
		"rule_id":         rule.Rule().ID(),
		"rule_action":     tx.Interruption().Action,
		"rule_disruptive": rule.Disruptive(),
		"rule_tags":       rule.Rule().Tags(),
		"rule_file":       rule.Rule().File(),
		"rule_file_line":  rule.Rule().Line(),
		"rule_revision":   rule.Rule().Revision(),
		"rule_secmark":    rule.Rule().SecMark(),
		"rule_accuracy":   rule.Rule().Accuracy(),

		//http contextual infos
		"upstream_addr": r.RemoteAddr,
		"req_uuid":      tx.ID(),
		"source_ip":     strings.Split(rule.ClientIPAddress(), ":")[0],
		"uri":           rule.URI(),
	}

	corazaEventB, err := json.Marshal(CorazaEvent)
	if err != nil {
		return evt, fmt.Errorf("Unable to marshal coraza alert: %w", err)
	}
	evt.Line = types.Line{
		Time: time.Now(),
		//should we add some info like listen addr/port/path ?
		Labels:  map[string]string{"type": "waf"},
		Process: true,
		Module:  "waf",
		Src:     "waf",
		Raw:     string(corazaEventB),
	}

	return evt, nil
}

func (w *WafSource) wafHandler(rw http.ResponseWriter, r *http.Request) {
	log.Printf("yolo here  %v", r)
	//let's gen a transaction id to keep consistance accross in-band and out-of-band
	uuid := uuid.New().String()
	//inband first
	in, tx, err := processReqWithEngine(w.inBandWaf, r, uuid)
	if err != nil { //things went south
		log.Errorf("Error while processing request : %s", err)
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	if in != nil {
		events, err := w.TxToEvents(tx, r)
		log.Infof("Request blocked by WAF, %d events to send", len(events))
		for _, evt := range events {
			w.outChan <- evt
		}
		log.Infof("done")
		if err != nil {
			log.Errorf("Cannot convert transaction to events : %s", err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	rw.WriteHeader(http.StatusOK)
	//Now we can do out of band
	in2, tx2, err := processReqWithEngine(w.outOfBandWaf, r, uuid)
	if err != nil { //things went south
		log.Errorf("Error while processing request : %s", err)
		return
	}
	if in2 != nil {
		events, err := w.TxToEvents(tx2, r)
		log.Infof("Request triggered by WAF, %d events to send", len(events))
		for _, evt := range events {
			w.outChan <- evt
		}
		if err != nil {
			log.Errorf("Cannot convert transaction to events : %s", err)
		}
		log.Infof("done")
		log.Infof("WAF triggered : %+v", in2)
		return
	}
}
