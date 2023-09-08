package wafacquisition

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corazatypes "github.com/crowdsecurity/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/crowdsecurity/go-cs-lib/trace"
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

// configuration structure of the acquis for the Waap
type WaapSourceConfig struct {
	ListenAddr                        string `yaml:"listen_addr"`
	ListenPort                        int    `yaml:"listen_port"`
	CertFilePath                      string `yaml:"cert_file"`
	KeyFilePath                       string `yaml:"key_file"`
	Path                              string `yaml:"path"`
	Routines                          int    `yaml:"routines"`
	Debug                             bool   `yaml:"debug"`
	WaapConfig                        string `yaml:"waap_config"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

// runtime structure of WaapSourceConfig
type WaapSource struct {
	config      WaapSourceConfig
	logger      *log.Entry
	mux         *http.ServeMux
	server      *http.Server
	addr        string
	outChan     chan types.Event
	InChan      chan waf.ParsedRequest
	WaapRuntime *waf.WaapRuntimeConfig

	WaapRunners []WaapRunner //one for each go-routine
}

func (wc *WaapSource) UnmarshalConfig(yamlConfig []byte) error {
	err := yaml.UnmarshalStrict(yamlConfig, wc.config)
	if err != nil {
		return errors.Wrap(err, "Cannot parse waf configuration")
	}

	if wc.config.ListenAddr == "" {
		return fmt.Errorf("listen_addr cannot be empty")
	}

	if wc.config.ListenPort == 0 {
		return fmt.Errorf("listen_port cannot be empty")
	}

	if wc.config.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	if wc.config.Path[0] != '/' {
		wc.config.Path = "/" + wc.config.Path
	}

	if wc.config.Mode == "" {
		wc.config.Mode = configuration.TAIL_MODE
	}

	// always have at least one waf routine
	if wc.config.Routines == 0 {
		wc.config.Routines = 1
	}
	return nil
}

func (w *WaapSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (w *WaapSource) GetAggregMetrics() []prometheus.Collector {
	return nil
}

func logError(error corazatypes.MatchedRule) {
	msg := error.ErrorLog()
	log.Infof("[logError][%s]  %s", error.Rule().Severity(), msg)
}

func (w *WaapSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	wc := WaapSourceConfig{}
	err := w.UnmarshalConfig(yamlConfig)
	if err != nil {
		return errors.Wrap(err, "unable to parse waf configuration")
	}
	w.logger = logger
	w.config = wc

	w.logger.Tracef("WAF configuration: %+v", w.config)

	w.addr = fmt.Sprintf("%s:%d", wc.ListenAddr, wc.ListenPort)

	w.mux = http.NewServeMux()

	w.server = &http.Server{
		Addr:    w.addr,
		Handler: w.mux,
	}

	w.InChan = make(chan waf.ParsedRequest)
	w.WaapRunners = make([]WaapRunner, wc.Routines)

	for nbRoutine := 0; nbRoutine < wc.Routines; nbRoutine++ {

		wafUUID := uuid.New().String()
		wafLogger := &log.Entry{}

		//configure logger
		if wc.Debug {
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

		runner := WaapRunner{
			inChan: w.InChan,
			UUID:   wafUUID,
			logger: wafLogger,
		}
		w.WaapRunners[nbRoutine] = runner
		//most likely missign somethign here to actually start the runner :)
	}

	w.logger.Infof("Created %d waf runners", len(w.WaapRunners))

	//We don´t use the wrapper provided by coraza because we want to fully control what happens when a rule match to send the information in crowdsec
	w.mux.HandleFunc(w.config.Path, w.waapHandler)

	return nil
}

func (w *WaapSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return fmt.Errorf("WAF datasource does not support command line acquisition")
}

func (w *WaapSource) GetMode() string {
	return w.config.Mode
}

func (w *WaapSource) GetName() string {
	return "waf"
}

func (w *WaapSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("WAF datasource does not support command line acquisition")
}

func (w *WaapSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	w.outChan = out
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/waf/live")

		w.logger.Infof("%d waf runner to start", len(w.WaapRunners))
		for _, runner := range w.WaapRunners {
			runner := runner
			runner.outChan = out
			t.Go(func() error {
				defer trace.CatchPanic("crowdsec/acquis/waf/live/runner")
				return runner.Run(t)
			})
		}

		w.logger.Infof("Starting WAF server on %s:%d%s", w.config.ListenAddr, w.config.ListenPort, w.config.Path)
		t.Go(func() error {
			var err error
			if w.config.CertFilePath != "" && w.config.KeyFilePath != "" {
				err = w.server.ListenAndServeTLS(w.config.CertFilePath, w.config.KeyFilePath)
			} else {
				err = w.server.ListenAndServe()
			}

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

func (w *WaapSource) CanRun() error {
	return nil
}

func (w *WaapSource) GetUuid() string {
	return w.config.UniqueId
}

func (w *WaapSource) Dump() interface{} {
	return w
}

type BodyResponse struct {
	Action string `json:"action"`
}

// should this be in the runner ?
func (w *WaapSource) waapHandler(rw http.ResponseWriter, r *http.Request) {
	// parse the request only once
	parsedRequest, err := waf.NewParsedRequestFromRequest(r)
	if err != nil {
		log.Errorf("%s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.InChan <- parsedRequest

	message := <-parsedRequest.ResponseChannel

	if message.Err != nil {
		log.Errorf("Error while processing InBAND: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	//here we must rely on WaapRuntimeConfig to know what to do
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
		log.Errorf("unable to marshal response: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
	} else {
		rw.Write(body)
	}

}
