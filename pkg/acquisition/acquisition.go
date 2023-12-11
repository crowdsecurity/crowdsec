package acquisition

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	appsecacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec"
	cloudwatchacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/cloudwatch"
	dockeracquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker"
	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	journalctlacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/journalctl"
	kafkaacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kafka"
	kinesisacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kinesis"
	k8sauditacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kubernetesaudit"
	lokiacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
	s3acquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/s3"
	syslogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog"
	wineventlogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/wineventlog"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type DataSourceUnavailableError struct {
	Name string
	Err  error
}

func (e *DataSourceUnavailableError) Error() string {
	return fmt.Sprintf("datasource '%s' is not available: %v", e.Name, e.Err)
}

func (e *DataSourceUnavailableError) Unwrap() error {
	return e.Err
}

// The interface each datasource must implement
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

var AcquisitionSources = map[string]func() DataSource{
	"file":        func() DataSource { return &fileacquisition.FileSource{} },
	"journalctl":  func() DataSource { return &journalctlacquisition.JournalCtlSource{} },
	"cloudwatch":  func() DataSource { return &cloudwatchacquisition.CloudwatchSource{} },
	"syslog":      func() DataSource { return &syslogacquisition.SyslogSource{} },
	"docker":      func() DataSource { return &dockeracquisition.DockerSource{} },
	"kinesis":     func() DataSource { return &kinesisacquisition.KinesisSource{} },
	"wineventlog": func() DataSource { return &wineventlogacquisition.WinEventLogSource{} },
	"kafka":       func() DataSource { return &kafkaacquisition.KafkaSource{} },
	"k8s-audit":   func() DataSource { return &k8sauditacquisition.KubernetesAuditSource{} },
	"loki":        func() DataSource { return &lokiacquisition.LokiSource{} },
	"s3":          func() DataSource { return &s3acquisition.S3Source{} },
	"appsec":      func() DataSource { return &appsecacquisition.AppsecSource{} },
}

var transformRuntimes = map[string]*vm.Program{}

func GetDataSourceIface(dataSourceType string) DataSource {
	source := AcquisitionSources[dataSourceType]
	if source == nil {
		return nil
	}
	return source()
}

// DataSourceConfigure creates and returns a DataSource object from a configuration,
// if the configuration is not valid it returns an error.
// If the datasource can't be run (eg. journalctl not available), it still returns an error which
// can be checked for the appropriate action.
func DataSourceConfigure(commonConfig configuration.DataSourceCommonCfg) (*DataSource, error) {
	// we dump it back to []byte, because we want to decode the yaml blob twice:
	// once to DataSourceCommonCfg, and then later to the dedicated type of the datasource
	yamlConfig, err := yaml.Marshal(commonConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal back interface: %w", err)
	}
	if dataSrc := GetDataSourceIface(commonConfig.Source); dataSrc != nil {
		/* this logger will then be used by the datasource at runtime */
		clog := log.New()
		if err := types.ConfigureLogger(clog); err != nil {
			return nil, fmt.Errorf("while configuring datasource logger: %w", err)
		}
		if commonConfig.LogLevel != nil {
			clog.SetLevel(*commonConfig.LogLevel)
		}
		customLog := log.Fields{
			"type": commonConfig.Source,
		}
		if commonConfig.Name != "" {
			customLog["name"] = commonConfig.Name
		}
		subLogger := clog.WithFields(customLog)
		/* check eventual dependencies are satisfied (ie. journald will check journalctl availability) */
		if err := dataSrc.CanRun(); err != nil {
			return nil, &DataSourceUnavailableError{Name: commonConfig.Source, Err: err}
		}
		/* configure the actual datasource */
		if err := dataSrc.Configure(yamlConfig, subLogger); err != nil {
			return nil, fmt.Errorf("failed to configure datasource %s: %w", commonConfig.Source, err)

		}
		return &dataSrc, nil
	}
	return nil, fmt.Errorf("cannot find source %s", commonConfig.Source)
}

// detectBackwardCompatAcquis: try to magically detect the type for backward compat (type was not mandatory then)
func detectBackwardCompatAcquis(sub configuration.DataSourceCommonCfg) string {
	if _, ok := sub.Config["filename"]; ok {
		return "file"
	}
	if _, ok := sub.Config["filenames"]; ok {
		return "file"
	}
	if _, ok := sub.Config["journalctl_filter"]; ok {
		return "journalctl"
	}
	return ""
}

func LoadAcquisitionFromDSN(dsn string, labels map[string]string, transformExpr string) ([]DataSource, error) {
	var sources []DataSource

	frags := strings.Split(dsn, ":")
	if len(frags) == 1 {
		return nil, fmt.Errorf("%s isn't valid dsn (no protocol)", dsn)
	}
	dataSrc := GetDataSourceIface(frags[0])
	if dataSrc == nil {
		return nil, fmt.Errorf("no acquisition for protocol %s://", frags[0])
	}
	/* this logger will then be used by the datasource at runtime */
	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return nil, fmt.Errorf("while configuring datasource logger: %w", err)
	}
	subLogger := clog.WithFields(log.Fields{
		"type": dsn,
	})
	uniqueId := uuid.NewString()
	if transformExpr != "" {
		vm, err := expr.Compile(transformExpr, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return nil, fmt.Errorf("while compiling transform expression '%s': %w", transformExpr, err)
		}
		transformRuntimes[uniqueId] = vm
	}
	err := dataSrc.ConfigureByDSN(dsn, labels, subLogger, uniqueId)
	if err != nil {
		return nil, fmt.Errorf("while configuration datasource for %s: %w", dsn, err)
	}
	sources = append(sources, dataSrc)
	return sources, nil
}

// LoadAcquisitionFromFile unmarshals the configuration item and checks its availability
func LoadAcquisitionFromFile(config *csconfig.CrowdsecServiceCfg) ([]DataSource, error) {
	var sources []DataSource

	for _, acquisFile := range config.AcquisitionFiles {
		log.Infof("loading acquisition file : %s", acquisFile)
		yamlFile, err := os.Open(acquisFile)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(yamlFile)
		dec.SetStrict(true)
		idx := -1
		for {
			var sub configuration.DataSourceCommonCfg
			err = dec.Decode(&sub)
			idx += 1
			if err != nil {
				if !errors.Is(err, io.EOF) {
					return nil, fmt.Errorf("failed to yaml decode %s: %w", acquisFile, err)
				}
				log.Tracef("End of yaml file")
				break
			}

			//for backward compat ('type' was not mandatory, detect it)
			if guessType := detectBackwardCompatAcquis(sub); guessType != "" {
				sub.Source = guessType
			}
			//it's an empty item, skip it
			if len(sub.Labels) == 0 {
				if sub.Source == "" {
					log.Debugf("skipping empty item in %s", acquisFile)
					continue
				}
				return nil, fmt.Errorf("missing labels in %s (position: %d)", acquisFile, idx)
			}
			if sub.Source == "" {
				return nil, fmt.Errorf("data source type is empty ('source') in %s (position: %d)", acquisFile, idx)
			}
			if GetDataSourceIface(sub.Source) == nil {
				return nil, fmt.Errorf("unknown data source %s in %s (position: %d)", sub.Source, acquisFile, idx)
			}
			uniqueId := uuid.NewString()
			sub.UniqueId = uniqueId
			src, err := DataSourceConfigure(sub)
			if err != nil {
				var dserr *DataSourceUnavailableError
				if errors.As(err, &dserr) {
					log.Error(err)
					continue
				}
				return nil, fmt.Errorf("while configuring datasource of type %s from %s (position: %d): %w", sub.Source, acquisFile, idx, err)
			}
			if sub.TransformExpr != "" {
				vm, err := expr.Compile(sub.TransformExpr, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
				if err != nil {
					return nil, fmt.Errorf("while compiling transform expression '%s' for datasource %s in %s (position: %d): %w", sub.TransformExpr, sub.Source, acquisFile, idx, err)
				}
				transformRuntimes[uniqueId] = vm
			}
			sources = append(sources, *src)
		}
	}
	return sources, nil
}

func GetMetrics(sources []DataSource, aggregated bool) error {
	var metrics []prometheus.Collector
	for i := 0; i < len(sources); i++ {
		if aggregated {
			metrics = sources[i].GetMetrics()
		} else {
			metrics = sources[i].GetAggregMetrics()
		}
		for _, metric := range metrics {
			if err := prometheus.Register(metric); err != nil {
				if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
					return fmt.Errorf("could not register metrics for datasource %s: %w", sources[i].GetName(), err)
				}
				// ignore the error
			}
		}
	}
	return nil
}

func transform(transformChan chan types.Event, output chan types.Event, AcquisTomb *tomb.Tomb, transformRuntime *vm.Program, logger *log.Entry) {
	defer trace.CatchPanic("crowdsec/acquis")
	logger.Infof("transformer started")
	for {
		select {
		case <-AcquisTomb.Dying():
			logger.Debugf("transformer is dying")
			return
		case evt := <-transformChan:
			logger.Tracef("Received event %s", evt.Line.Raw)
			out, err := expr.Run(transformRuntime, map[string]interface{}{"evt": &evt})
			if err != nil {
				logger.Errorf("while running transform expression: %s, sending event as-is", err)
				output <- evt
			}
			if out == nil {
				logger.Errorf("transform expression returned nil, sending event as-is")
				output <- evt
			}
			switch v := out.(type) {
			case string:
				logger.Tracef("transform expression returned %s", v)
				evt.Line.Raw = v
				output <- evt
			case []interface{}:
				logger.Tracef("transform expression returned %v", v) //nolint:asasalint // We actually want to log the slice content
				for _, line := range v {
					l, ok := line.(string)
					if !ok {
						logger.Errorf("transform expression returned []interface{}, but cannot assert an element to string")
						output <- evt
						continue
					}
					evt.Line.Raw = l
					output <- evt
				}
			case []string:
				logger.Tracef("transform expression returned %v", v)
				for _, line := range v {
					evt.Line.Raw = line
					output <- evt
				}
			default:
				logger.Errorf("transform expression returned an invalid type %T, sending event as-is", out)
				output <- evt
			}
		}
	}
}

func StartAcquisition(sources []DataSource, output chan types.Event, AcquisTomb *tomb.Tomb) error {
	// Don't wait if we have no sources, as it will hang forever
	if len(sources) == 0 {
		return nil
	}

	for i := 0; i < len(sources); i++ {
		subsrc := sources[i] //ensure its a copy
		log.Debugf("starting one source %d/%d ->> %T", i, len(sources), subsrc)

		AcquisTomb.Go(func() error {
			defer trace.CatchPanic("crowdsec/acquis")
			var err error

			outChan := output
			log.Debugf("datasource %s UUID: %s", subsrc.GetName(), subsrc.GetUuid())
			if transformRuntime, ok := transformRuntimes[subsrc.GetUuid()]; ok {
				log.Infof("transform expression found for datasource %s", subsrc.GetName())
				transformChan := make(chan types.Event)
				outChan = transformChan
				transformLogger := log.WithFields(log.Fields{
					"component":  "transform",
					"datasource": subsrc.GetName(),
				})
				AcquisTomb.Go(func() error {
					transform(outChan, output, AcquisTomb, transformRuntime, transformLogger)
					return nil
				})
			}
			if subsrc.GetMode() == configuration.TAIL_MODE {
				err = subsrc.StreamingAcquisition(outChan, AcquisTomb)
			} else {
				err = subsrc.OneShotAcquisition(outChan, AcquisTomb)
			}
			if err != nil {
				//if one of the acqusition returns an error, we kill the others to properly shutdown
				AcquisTomb.Kill(err)
			}
			return nil
		})
	}

	/*return only when acquisition is over (cat) or never (tail)*/
	err := AcquisTomb.Wait()
	return err
}
