package wafacquisition

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type WafSource struct {
	config  WafSourceConfig
	logger  *log.Entry
	mux     *http.ServeMux
	server  *http.Server
	addr    string
	outChan chan types.Event
	waf     coraza.WAF
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
		return errors.Wrap(err, "Cannot parse k8s-audit configuration")
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

	crowdsecWafConfig := waf.NewWafConfig()

	err = crowdsecWafConfig.LoadWafRules()

	if err != nil {
		return fmt.Errorf("Cannot load WAF rules: %w", err)
	}

	var rules string

	for _, rule := range crowdsecWafConfig.InbandRules {
		rules += rule.String() + "\n"
	}

	w.logger.Infof("Loading rules %+v", rules)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rules))

	if err != nil {
		return errors.Wrap(err, "Cannot create WAF")
	}

	w.waf = waf

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

func (w *WafSource) wafHandler(rw http.ResponseWriter, r *http.Request) {
	tx := w.waf.NewTransaction()

	if tx.IsRuleEngineOff() {
		//Not enabled, just return
		rw.WriteHeader(http.StatusOK)
		return
	}

	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

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
		w.logger.Warnf("WAF blocked request: %+v", in)
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	in = tx.ProcessRequestHeaders()

	if in != nil {
		w.logger.Warnf("WAF blocked request: %+v", in)
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	if tx.IsRequestBodyAccessible() {
		if r.Body != nil && r.Body != http.NoBody {
			_, _, err := tx.ReadRequestBodyFrom(r.Body)
			if err != nil {
				w.logger.Errorf("Cannot read request body: %s", err)
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			bodyReader, err := tx.RequestBodyReader()
			if err != nil {
				w.logger.Errorf("Cannot read request body: %s", err)
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			body := io.MultiReader(bodyReader, r.Body)
			r.Body = ioutil.NopCloser(body)
			in, err = tx.ProcessRequestBody()
			if err != nil {
				w.logger.Errorf("Cannot process request body: %s", err)
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			if in != nil {
				w.logger.Warnf("WAF blocked request: %+v", in)
				rw.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}

	rw.WriteHeader(http.StatusOK)
}
