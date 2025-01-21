package acquisition

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
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
	GetMetrics() []prometheus.Collector                                       // Returns pointers to metrics that are managed by the module
	GetAggregMetrics() []prometheus.Collector                                 // Returns pointers to metrics that are managed by the module (aggregated mode, limits cardinality)
	UnmarshalConfig([]byte) error                                             // Decode and pre-validate the YAML datasource - anything that can be checked before runtime
	Configure([]byte, *log.Entry, int) error                                  // Complete the YAML datasource configuration and perform runtime checks.
	ConfigureByDSN(string, map[string]string, *log.Entry, string) error       // Configure the datasource
	GetMode() string                                                          // Get the mode (TAIL, CAT or SERVER)
	GetName() string                                                          // Get the name of the module
	OneShotAcquisition(context.Context, chan types.Event, *tomb.Tomb) error   // Start one shot acquisition(eg, cat a file)
	StreamingAcquisition(context.Context, chan types.Event, *tomb.Tomb) error // Start live acquisition (eg, tail a file)
	CanRun() error                                                            // Whether the datasource can run or not (eg, journalctl on BSD is a non-sense)
	GetUuid() string                                                          // Get the unique identifier of the datasource
	Dump() interface{}
}

var (
	// We declare everything here so we can tell if they are unsupported, or excluded from the build
	AcquisitionSources = map[string]func() DataSource{}
	transformRuntimes  = map[string]*vm.Program{}
)

func GetDataSourceIface(dataSourceType string) (DataSource, error) {
	source, registered := AcquisitionSources[dataSourceType]
	if registered {
		return source(), nil
	}

	built, known := component.Built["datasource_"+dataSourceType]

	if !known {
		return nil, fmt.Errorf("unknown data source %s", dataSourceType)
	}

	if built {
		panic("datasource " + dataSourceType + " is built but not registered")
	}

	return nil, fmt.Errorf("data source %s is not built in this version of crowdsec", dataSourceType)
}

// registerDataSource registers a datasource in the AcquisitionSources map.
// It must be called in the init() function of the datasource package, and the datasource name
// must be declared with a nil value in the map, to allow for conditional compilation.
func registerDataSource(dataSourceType string, dsGetter func() DataSource) {
	component.Register("datasource_" + dataSourceType)

	AcquisitionSources[dataSourceType] = dsGetter
}

// setupLogger creates a logger for the datasource to use at runtime.
func setupLogger(source, name string, level *log.Level) (*log.Entry, error) {
	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return nil, fmt.Errorf("while configuring datasource logger: %w", err)
	}

	if level != nil {
		clog.SetLevel(*level)
	}

	fields := log.Fields{
		"type": source,
	}

	if name != "" {
		fields["name"] = name
	}

	subLogger := clog.WithFields(fields)

	return subLogger, nil
}

// DataSourceConfigure creates and returns a DataSource object from a configuration,
// if the configuration is not valid it returns an error.
// If the datasource can't be run (eg. journalctl not available), it still returns an error which
// can be checked for the appropriate action.
func DataSourceConfigure(commonConfig configuration.DataSourceCommonCfg, metricsLevel int) (DataSource, error) {
	// we dump it back to []byte, because we want to decode the yaml blob twice:
	// once to DataSourceCommonCfg, and then later to the dedicated type of the datasource
	yamlConfig, err := yaml.Marshal(commonConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize back interface: %w", err)
	}

	dataSrc, err := GetDataSourceIface(commonConfig.Source)
	if err != nil {
		return nil, err
	}

	subLogger, err := setupLogger(commonConfig.Source, commonConfig.Name, commonConfig.LogLevel)
	if err != nil {
		return nil, err
	}

	/* check eventual dependencies are satisfied (ie. journald will check journalctl availability) */
	if err := dataSrc.CanRun(); err != nil {
		return nil, &DataSourceUnavailableError{Name: commonConfig.Source, Err: err}
	}
	/* configure the actual datasource */
	if err := dataSrc.Configure(yamlConfig, subLogger, metricsLevel); err != nil {
		return nil, err
	}

	return dataSrc, nil
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
	frags := strings.Split(dsn, ":")
	if len(frags) == 1 {
		return nil, fmt.Errorf("%s isn't valid dsn (no protocol)", dsn)
	}

	dataSrc, err := GetDataSourceIface(frags[0])
	if err != nil {
		return nil, fmt.Errorf("no acquisition for protocol %s:// - %w", frags[0], err)
	}

	subLogger, err := setupLogger(dsn, "", nil)
	if err != nil {
		return nil, err
	}

	uniqueId := uuid.NewString()

	if transformExpr != "" {
		vm, err := expr.Compile(transformExpr, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return nil, fmt.Errorf("while compiling transform expression '%s': %w", transformExpr, err)
		}

		transformRuntimes[uniqueId] = vm
	}

	err = dataSrc.ConfigureByDSN(dsn, labels, subLogger, uniqueId)
	if err != nil {
		return nil, fmt.Errorf("while configuration datasource for %s: %w", dsn, err)
	}

	return []DataSource{dataSrc}, nil
}

func GetMetricsLevelFromPromCfg(prom *csconfig.PrometheusCfg) int {
	if prom == nil {
		return configuration.METRICS_FULL
	}

	if !prom.Enabled {
		return configuration.METRICS_NONE
	}

	if prom.Level == configuration.CFG_METRICS_AGGREGATE {
		return configuration.METRICS_AGGREGATE
	}

	if prom.Level == configuration.CFG_METRICS_FULL {
		return configuration.METRICS_FULL
	}

	return configuration.METRICS_FULL
}

// LoadAcquisitionFromFile unmarshals the configuration item and checks its availability
func LoadAcquisitionFromFile(config *csconfig.CrowdsecServiceCfg, prom *csconfig.PrometheusCfg) ([]DataSource, error) {
	var sources []DataSource

	metrics_level := GetMetricsLevelFromPromCfg(prom)

	for _, acquisFile := range config.AcquisitionFiles {
		log.Infof("loading acquisition file : %s", acquisFile)

		yamlFile, err := os.Open(acquisFile)
		if err != nil {
			return nil, err
		}

		defer yamlFile.Close()

		acquisContent, err := io.ReadAll(yamlFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", acquisFile, err)
		}

		expandedAcquis := csstring.StrictExpand(string(acquisContent), os.LookupEnv)

		dec := yaml.NewDecoder(strings.NewReader(expandedAcquis))
		dec.SetStrict(true)

		idx := -1

		for {
			var sub configuration.DataSourceCommonCfg

			idx += 1

			err = dec.Decode(&sub)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					return nil, fmt.Errorf("failed to parse %s: %w", acquisFile, err)
				}

				log.Tracef("End of yaml file")

				break
			}

			// for backward compat ('type' was not mandatory, detect it)
			if guessType := detectBackwardCompatAcquis(sub); guessType != "" {
				log.Debugf("datasource type missing in %s (position %d): detected 'source=%s'", acquisFile, idx, guessType)

				if sub.Source != "" && sub.Source != guessType {
					log.Warnf("datasource type mismatch in %s (position %d): found '%s' but should probably be '%s'", acquisFile, idx, sub.Source, guessType)
				}

				sub.Source = guessType
			}
			// it's an empty item, skip it
			if len(sub.Labels) == 0 {
				if sub.Source == "" {
					log.Debugf("skipping empty item in %s", acquisFile)
					continue
				}

				if sub.Source != "docker" {
					// docker is the only source that can be empty
					return nil, fmt.Errorf("missing labels in %s (position %d)", acquisFile, idx)
				}
			}

			if sub.Source == "" {
				return nil, fmt.Errorf("data source type is empty ('source') in %s (position %d)", acquisFile, idx)
			}

			// pre-check that the source is valid
			_, err := GetDataSourceIface(sub.Source)
			if err != nil {
				return nil, fmt.Errorf("in file %s (position %d) - %w", acquisFile, idx, err)
			}

			uniqueId := uuid.NewString()
			sub.UniqueId = uniqueId

			src, err := DataSourceConfigure(sub, metrics_level)
			if err != nil {
				var dserr *DataSourceUnavailableError
				if errors.As(err, &dserr) {
					log.Error(err)
					continue
				}

				return nil, fmt.Errorf("while configuring datasource of type %s from %s (position %d): %w", sub.Source, acquisFile, idx, err)
			}

			if sub.TransformExpr != "" {
				vm, err := expr.Compile(sub.TransformExpr, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
				if err != nil {
					return nil, fmt.Errorf("while compiling transform expression '%s' for datasource %s in %s (position %d): %w", sub.TransformExpr, sub.Source, acquisFile, idx, err)
				}

				transformRuntimes[uniqueId] = vm
			}

			sources = append(sources, src)
		}
	}

	return sources, nil
}

func GetMetrics(sources []DataSource, aggregated bool) error {
	var metrics []prometheus.Collector

	for i := range sources {
		if aggregated {
			metrics = sources[i].GetMetrics()
		} else {
			metrics = sources[i].GetAggregMetrics()
		}

		for _, metric := range metrics {
			if err := prometheus.Register(metric); err != nil {
				var alreadyRegisteredErr prometheus.AlreadyRegisteredError
				if !errors.As(err, &alreadyRegisteredErr) {
					return fmt.Errorf("could not register metrics for datasource %s: %w", sources[i].GetName(), err)
				}
				// ignore the error
			}
		}
	}

	return nil
}

// There's no need for an actual deep copy
// The event is almost empty, we are mostly interested in allocating new maps for Parsed/Meta/...
func copyEvent(evt types.Event, line string) types.Event {
	evtCopy := types.MakeEvent(evt.ExpectMode == types.TIMEMACHINE, evt.Type, evt.Process)
	evtCopy.Line = evt.Line
	evtCopy.Line.Raw = line
	evtCopy.Line.Labels = make(map[string]string)

	for k, v := range evt.Line.Labels {
		evtCopy.Line.Labels[k] = v
	}

	return evtCopy
}

func transform(transformChan chan types.Event, output chan types.Event, acquisTomb *tomb.Tomb, transformRuntime *vm.Program, logger *log.Entry) {
	defer trace.CatchPanic("crowdsec/acquis")
	logger.Infof("transformer started")

	for {
		select {
		case <-acquisTomb.Dying():
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
				output <- copyEvent(evt, v)
			case []interface{}:
				logger.Tracef("transform expression returned %v", v) //nolint:asasalint // We actually want to log the slice content

				for _, line := range v {
					l, ok := line.(string)
					if !ok {
						logger.Errorf("transform expression returned []interface{}, but cannot assert an element to string")
						output <- evt

						continue
					}

					output <- copyEvent(evt, l)
				}
			case []string:
				logger.Tracef("transform expression returned %v", v)

				for _, line := range v {
					output <- copyEvent(evt, line)
				}
			default:
				logger.Errorf("transform expression returned an invalid type %T, sending event as-is", out)
				output <- evt
			}
		}
	}
}

func StartAcquisition(ctx context.Context, sources []DataSource, output chan types.Event, acquisTomb *tomb.Tomb) error {
	// Don't wait if we have no sources, as it will hang forever
	if len(sources) == 0 {
		return nil
	}

	for i := range sources {
		subsrc := sources[i] // ensure its a copy
		log.Debugf("starting one source %d/%d ->> %T", i, len(sources), subsrc)

		acquisTomb.Go(func() error {
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

				acquisTomb.Go(func() error {
					transform(outChan, output, acquisTomb, transformRuntime, transformLogger)
					return nil
				})
			}

			if subsrc.GetMode() == configuration.TAIL_MODE {
				err = subsrc.StreamingAcquisition(ctx, outChan, acquisTomb)
			} else {
				err = subsrc.OneShotAcquisition(ctx, outChan, acquisTomb)
			}

			if err != nil {
				// if one of the acqusition returns an error, we kill the others to properly shutdown
				acquisTomb.Kill(err)
			}

			return nil
		})
	}

	/*return only when acquisition is over (cat) or never (tail)*/
	err := acquisTomb.Wait()

	return err
}
