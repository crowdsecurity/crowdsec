package acquisition

import (
	"fmt"
	"io"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	/*
	   ---
	   type: nginx
	   source: journald
	   filter: "PROG=nginx"
	   ---
	   type: nginx
	   source: files
	   filenames:
	    - "/var/log/nginx/*.log"
	   ---

	   filename: /tmp/test.log
	   labels:
	     type: nginx
	   ---
	   journalctl_filter: xxxx
	   labels:
	     type: nginx
	*/

	tomb "gopkg.in/tomb.v2"
	//"gopkg.in/yaml.v3"
)

var ReaderHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_reader_hits_total",
		Help: "Total lines where read.",
	},
	[]string{"source"},
)

var TAIL_MODE = "tail"
var CAT_MODE = "cat"

type DataSourceCfg struct {
	//Type              string            `yaml:"type,omitempty"` //file|bin|...
	Mode              string            `yaml:"mode,omitempty"` //tail|cat|...
	Filename          string            `yaml:"filename,omitempty"`
	Filenames         []string          `yaml:"filenames,omitempty"`
	JournalctlFilters []string          `yaml:"journalctl_filter,omitempty"`
	Labels            map[string]string `yaml:"labels,omitempty"`
	Profiling         bool              `yaml:"profiling,omitempty"`
}

type DataSource interface {
	Configure(DataSourceCfg) error
	//Exists() (bool, error)
	/*add a type parameter ?*/
	StartTail(chan types.Event, *tomb.Tomb) error
	StartCat(chan types.Event, *tomb.Tomb) error
	//Label() string
}

func LoadAcquisitionConfig(config *csconfig.CrowdsecServiceCfg) ([]DataSource, error) {

	var sources []DataSource

	yamlFile, err := os.Open(config.AcquisitionFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "can't open %s", config.AcquisitionFilePath)
	}
	//process the yaml
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	for {
		t := DataSourceCfg{}
		err = dec.Decode(&t)
		if err != nil {
			if err == io.EOF {
				log.Tracef("End of yaml file")
				break
			}
			return nil, errors.Wrap(err, fmt.Sprintf("failed to yaml decode %s", config.AcquisitionFilePath))
		}
		if t.Mode == "" { /*default mode is tail*/
			t.Mode = TAIL_MODE
		}
		/*it's file acquisition*/
		if len(t.Filename) > 0 || len(t.Filenames) > 0 {
			fileSrc := new(FileSource)
			if err := fileSrc.Configure(t); err != nil {
				log.Errorf("Bad acquisition configuration : %s", err)
				continue
			}
			sources = append(sources, fileSrc)
		} else if len(t.JournalctlFilters) > 0 {
			journaldSrc := new(JournaldSource)
			if err := journaldSrc.Configure(t); err != nil {
				log.Errorf("Bad acquisition configuration : %s", err)
				continue
			}
			sources = append(sources, journaldSrc)
		}
	}
	return sources, nil
}

func StartAcquisition(sources []DataSource, output chan types.Event) error {
	var AcquisTomb tomb.Tomb

	log.Printf("startiiiiing")
	for i := 0; i < len(sources); i++ {
		subsrc := sources[i]
		log.Printf("starting one source %d/%d ->> %T", i, len(sources), subsrc)
		AcquisTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis")
			if err := subsrc.StartTail(output, &AcquisTomb); err != nil {
				log.Errorf("in tail acquisition : %s", err)
				return err
			}
			return nil
		})
	}
	// for sidx, source := range sources {

	// }
	err := AcquisTomb.Wait()
	return err
}
