package acquisition

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/csyaml"
	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
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
	// identity, lifecycle
	GetMode() string                                                                                    // Get the mode (TAIL, CAT or SERVER)
	GetName() string                                                                                    // Get the name of the module
	GetUuid() string                                                                                    // Get the unique identifier of the datasource
	Dump() any
	CanRun() error                                                                                      // Whether the datasource can run or not (eg, journalctl on BSD is a non-sense)

	// configuration
	UnmarshalConfig(yamlConfig []byte) error                                                            // Decode and pre-validate the YAML datasource - anything that can be checked before runtime
	Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error // Complete the YAML datasource configuration and perform runtime checks.
}

type Fetcher interface {
	// Start one shot acquisition(eg, cat a file)
	OneShotAcquisition(ctx context.Context, out chan types.Event, acquisTomb *tomb.Tomb) error
}

type Tailer interface {
	// Start live acquisition (eg, tail a file)
	StreamingAcquisition(ctx context.Context, out chan types.Event, acquisTomb *tomb.Tomb) error
}

type MetricsProvider interface {
	// Returns pointers to metrics that are managed by the module
	GetMetrics() []prometheus.Collector

	// Returns pointers to metrics that are managed by the module (aggregated mode, limits cardinality)
	GetAggregMetrics() []prometheus.Collector
}

type DSNConfigurer interface {
	// Configure the datasource
	ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uniqueID string) error
}

var (
	// We register the datasources at init time so we can tell if they are unsupported, or excluded from the build
	AcquisitionSources = map[string]func() DataSource{}
	transformRuntimes  = map[string]*vm.Program{}
)

func GetDataSourceIface(dataSourceType string) (DataSource, error) {
	source, registered := AcquisitionSources[dataSourceType]
	if registered {
		return source(), nil
	}

	built, known := component.Built["datasource_"+dataSourceType]

	if dataSourceType == "" {
		return nil, errors.New("data source type is empty")
	}

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
	if err := types.ConfigureLogger(clog, level); err != nil {
		return nil, fmt.Errorf("while configuring datasource logger: %w", err)
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
func DataSourceConfigure(ctx context.Context, commonConfig configuration.DataSourceCommonCfg, yamlConfig []byte, metricsLevel metrics.AcquisitionMetricsLevel) (DataSource, error) {
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
	if err := dataSrc.Configure(ctx, yamlConfig, subLogger, metricsLevel); err != nil {
		return nil, err
	}

	return dataSrc, nil
}

func LoadAcquisitionFromDSN(ctx context.Context, dsn string, labels map[string]string, transformExpr string) ([]DataSource, error) {
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

	uniqueID := uuid.NewString()

	if transformExpr != "" {
		vm, err := expr.Compile(transformExpr, exprhelpers.GetExprOptions(map[string]any{"evt": &types.Event{}})...)
		if err != nil {
			return nil, fmt.Errorf("while compiling transform expression '%s': %w", transformExpr, err)
		}

		transformRuntimes[uniqueID] = vm
	}

	dsnConf, ok := dataSrc.(DSNConfigurer)
	if !ok {
		return nil, fmt.Errorf("%s datasource does not support command-line acquisition", frags[0])
	}

	if err = dsnConf.ConfigureByDSN(ctx, dsn, labels, subLogger, uniqueID); err != nil {
		return nil, fmt.Errorf("while configuration datasource for %s: %w", dsn, err)
	}

	return []DataSource{dataSrc}, nil
}

func GetMetricsLevelFromPromCfg(prom *csconfig.PrometheusCfg) metrics.AcquisitionMetricsLevel {
	if prom == nil {
		return metrics.AcquisitionMetricsLevelFull
	}

	if !prom.Enabled {
		return metrics.AcquisitionMetricsLevelNone
	}

	if prom.Level == metrics.MetricsLevelNone {
		return metrics.AcquisitionMetricsLevelNone
	}

	if prom.Level == metrics.MetricsLevelAggregated {
		return metrics.AcquisitionMetricsLevelAggregated
	}

	if prom.Level == metrics.MetricsLevelFull {
		return metrics.AcquisitionMetricsLevelFull
	}

	return metrics.AcquisitionMetricsLevelFull
}

func detectType(r io.Reader) (string, error) {
	collectedKeys, err := csyaml.GetDocumentKeys(r)
	if err != nil {
		return "", err
	}

	if len(collectedKeys) == 0 {
		return "", nil
	}

	keys := collectedKeys[0]

	switch {
	case slices.Contains(keys, "source"):
		return "", nil
	case slices.Contains(keys, "filename"):
		return "file", nil
	case slices.Contains(keys, "filenames"):
		return "file", nil
	case slices.Contains(keys, "journalctl_filter"):
		return "journalctl", nil
	default:
		return "", nil
	}
}

// sourcesFromFile reads and parses one acquisition file into DataSources.
func sourcesFromFile(ctx context.Context, acquisFile string, metricsLevel metrics.AcquisitionMetricsLevel) ([]DataSource, error) {
	var sources []DataSource

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

	documents, err := csyaml.SplitDocuments(strings.NewReader(expandedAcquis))
	if err != nil {
		return nil, err
	}

	idx := -1

	for _, yamlDoc := range documents {
		detectedType, err := detectType(bytes.NewReader(yamlDoc))
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", yamlFile.Name(), err)
		}

		idx += 1

		var sub configuration.DataSourceCommonCfg

		// can't be strict here, the doc contains specific datasource config too but we won't collect them now.
		if err = yaml.UnmarshalWithOptions(yamlDoc, &sub); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", yamlFile.Name(), errors.New(yaml.FormatError(err, false, false)))
		}

		// for backward compat ('type' was not mandatory, detect it)
		if guessType := detectedType; guessType != "" {
			log.Debugf("datasource type missing in %s (position %d): detected 'source=%s'", acquisFile, idx, guessType)

			if sub.Source != "" && sub.Source != guessType {
				log.Warnf("datasource type mismatch in %s (position %d): found '%s' but should probably be '%s'", acquisFile, idx, sub.Source, guessType)
			}

			sub.Source = guessType
		}

		// it's an empty item, skip it

		empty, err := csyaml.IsEmptyYAML(bytes.NewReader(yamlDoc))
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s (position %d): %w", acquisFile, idx, err)
		}

		if empty {
			// there are no keys or only comments, skip the document
			continue
		}

		if len(sub.Labels) == 0 {
			if sub.Source != "docker" {
				// docker is the only source that can be empty
				return nil, fmt.Errorf("missing labels in %s (position %d)", acquisFile, idx)
			}
		}

		if sub.Source == "" {
			return nil, fmt.Errorf("missing 'source' field in %s (position %d)", acquisFile, idx)
		}

		// pre-check that the source is valid
		_, err = GetDataSourceIface(sub.Source)
		if err != nil {
			return nil, fmt.Errorf("in file %s (position %d) - %w", acquisFile, idx, err)
		}

		uniqueID := uuid.NewString()
		sub.UniqueId = uniqueID

		src, err := DataSourceConfigure(ctx, sub, yamlDoc, metricsLevel)
		if err != nil {
			var dserr *DataSourceUnavailableError
			if errors.As(err, &dserr) {
				log.Error(err)
				continue
			}

			return nil, fmt.Errorf("while configuring datasource of type %s from %s (position %d): %w", sub.Source, acquisFile, idx, err)
		}

		if sub.TransformExpr != "" {
			vm, err := expr.Compile(sub.TransformExpr, exprhelpers.GetExprOptions(map[string]any{"evt": &types.Event{}})...)
			if err != nil {
				return nil, fmt.Errorf("while compiling transform expression '%s' for datasource %s in %s (position %d): %w", sub.TransformExpr, sub.Source, acquisFile, idx, err)
			}

			transformRuntimes[uniqueID] = vm
		}

		sources = append(sources, src)
	}

	return sources, nil
}

// LoadAcquisitionFromFiles unmarshals the configuration item and checks its availability
func LoadAcquisitionFromFiles(ctx context.Context, config *csconfig.CrowdsecServiceCfg, prom *csconfig.PrometheusCfg) ([]DataSource, error) {
	var allSources []DataSource

	metricsLevel := GetMetricsLevelFromPromCfg(prom)

	for _, acquisFile := range config.AcquisitionFiles {
		sources, err := sourcesFromFile(ctx, acquisFile, metricsLevel)
		if err != nil {
			return nil, err
		}

		allSources = append(allSources, sources...)
	}

	return allSources, nil
}

func GetMetrics(sources []DataSource, aggregated bool) error {
	for i := range sources {
		mp, ok := sources[i].(MetricsProvider)
		if !ok {
			// the source does not expose metrics
			continue
		}

		var metrics []prometheus.Collector

		if aggregated {
			metrics = mp.GetMetrics()
		} else {
			metrics = mp.GetAggregMetrics()
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

	maps.Copy(evtCopy.Line.Labels, evt.Line.Labels)

	return evtCopy
}

func transform(transformChan chan types.Event, output chan types.Event, acquisTomb *tomb.Tomb, transformRuntime *vm.Program, logger *log.Entry) {
	defer trace.CatchPanic("crowdsec/acquis")

	logger.Info("transformer started")

	for {
		select {
		case <-acquisTomb.Dying():
			logger.Debugf("transformer is dying")
			return
		case evt := <-transformChan:
			logger.Tracef("Received event %s", evt.Line.Raw)

			out, err := expr.Run(transformRuntime, map[string]any{"evt": &evt})
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
			case []any:
				logger.Tracef("transform expression returned %v", v) // We actually want to log the slice content

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
				if s, ok := subsrc.(Tailer); ok {
					err = s.StreamingAcquisition(ctx, outChan, acquisTomb)
				} else {
					err = fmt.Errorf("%s: tail mode is set but StreamingAcquisition is not supported", subsrc.GetName())
				}
			} else {
				if s, ok := subsrc.(Fetcher); ok {
					err = s.OneShotAcquisition(ctx, outChan, acquisTomb)
				} else {
					err = fmt.Errorf("%s: cat mode is set but OneShotAcquisition is not supported", subsrc.GetName())
				}
			}

			if err != nil {
				// if one of the acqusition returns an error, we kill the others to properly shutdown
				acquisTomb.Kill(err)
			}

			return nil
		})
	}

	// return only when acquisition is over (cat) or never (tail)
	err := acquisTomb.Wait()

	return err
}
