package acquisition

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	journalctlacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/journalctl"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	tomb "gopkg.in/tomb.v2"
)

// The interface each datasource must implement
type DataSource interface {
	GetMetrics() []prometheus.Collector                      // Returns pointers to metrics that are managed by the module
	Configure([]byte, *log.Entry) error                      // Configure the datasource
	ConfigureByDSN(string, string, *log.Entry) error         // Configure the datasource
	GetMode() string                                         // Get the mode (TAIL, CAT or SERVER)
	GetName() string                                         // Get the name of the module
	OneShotAcquisition(chan types.Event, *tomb.Tomb) error   // Start one shot acquisition(eg, cat a file)
	StreamingAcquisition(chan types.Event, *tomb.Tomb) error // Start live acquisition (eg, tail a file)
	CanRun() error                                           // Whether the datasource can run or not (eg, journalctl on BSD is a non-sense)
	Dump() interface{}
}

var AcquisitionSources = []struct {
	name  string
	iface func() DataSource
}{
	{
		name:  "file",
		iface: func() DataSource { return &fileacquisition.FileSource{} },
	},
	{
		name:  "journalctl",
		iface: func() DataSource { return &journalctlacquisition.JournalCtlSource{} },
	},
}

func GetDataSourceIface(dataSourceType string) DataSource {
	for _, source := range AcquisitionSources {
		if source.name == dataSourceType {
			return source.iface()
		}
	}
	return nil
}

func DataSourceConfigure(commonConfig configuration.DataSourceCommonCfg) (*DataSource, error) {

	//we dump it back to []byte, because we want to decode the yaml blob twice :
	//once to DataSourceCommonCfg, and then later to the dedicated type of the datasource
	yamlConfig, err := yaml.Marshal(commonConfig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal back interface")
	}
	if dataSrc := GetDataSourceIface(commonConfig.Source); dataSrc != nil {
		/* this logger will then be used by the datasource at runtime */
		clog := log.New()
		if err := types.ConfigureLogger(clog); err != nil {
			return nil, errors.Wrap(err, "while configuring datasource logger")
		}
		if commonConfig.LogLevel != nil {
			clog.SetLevel(*commonConfig.LogLevel)
		}
		subLogger := clog.WithFields(log.Fields{
			"type": commonConfig.Source,
		})
		/* check eventual dependencies are satisfied (ie. journald will check journalctl availability) */
		if err := dataSrc.CanRun(); err != nil {
			return nil, errors.Wrapf(err, "datasource %s cannot be run", commonConfig.Source)
		}
		/* configure the actual datasource */
		if err := dataSrc.Configure(yamlConfig, subLogger); err != nil {
			return nil, errors.Wrapf(err, "failed to configure datasource %s", commonConfig.Source)

		}
		return &dataSrc, nil
	}
	return nil, fmt.Errorf("cannot find source %s", commonConfig.Source)
}

//detectBackwardCompatAcquis : try to magically detect the type for backward compat (type was not mandatory then)
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

func LoadAcquisitionFromDSN(dsn string, label string) ([]DataSource, error) {
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
		return nil, errors.Wrap(err, "while configuring datasource logger")
	}
	subLogger := clog.WithFields(log.Fields{
		"type": dsn,
	})
	err := dataSrc.ConfigureByDSN(dsn, label, subLogger)
	if err != nil {
		return nil, errors.Wrapf(err, "while configuration datasource for %s", dsn)
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
			return nil, errors.Wrapf(err, "can't open %s", acquisFile)
		}
		dec := yaml.NewDecoder(yamlFile)
		dec.SetStrict(true)
		for {
			var sub configuration.DataSourceCommonCfg
			err = dec.Decode(&sub)
			if err != nil {
				if err == io.EOF {
					log.Tracef("End of yaml file")
					break
				}
				return nil, errors.Wrapf(err, "failed to yaml decode %s", acquisFile)
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
				return nil, fmt.Errorf("missing labels in %s", acquisFile)
			}

			if GetDataSourceIface(sub.Source) == nil {
				return nil, fmt.Errorf("unknown data source %s in %s", sub.Source, acquisFile)
			}
			src, err := DataSourceConfigure(sub)
			if err != nil {
				return nil, errors.Wrapf(err, "while configuring datasource of type %s from %s", sub.Source, acquisFile)
			}
			sources = append(sources, *src)
		}
	}
	return sources, nil
}

func StartAcquisition(sources []DataSource, output chan types.Event, AcquisTomb *tomb.Tomb) error {
	for i := 0; i < len(sources); i++ {
		subsrc := sources[i] //ensure its a copy
		log.Debugf("starting one source %d/%d ->> %T", i, len(sources), subsrc)
		//register acquisition specific metrics
		for _, metrics := range subsrc.GetMetrics() {
			if err := prometheus.Register(metrics); err != nil {
				if _, ok := err.(prometheus.AlreadyRegisteredError); ok {
					//ignore the error
				} else {
					return errors.Wrapf(err, "could not register metrics for datasource %s", subsrc.GetName())
				}
			}
		}

		AcquisTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis")
			var err error
			if subsrc.GetMode() == configuration.TAIL_MODE {
				err = subsrc.StreamingAcquisition(output, AcquisTomb)
			} else {
				err = subsrc.OneShotAcquisition(output, AcquisTomb)
			}
			if err != nil {
				return err
			}
			return nil
		})
	}
	/*return only when acquisition is over (cat) or never (tail)*/
	err := AcquisTomb.Wait()
	return err
}
