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

type DataSourceCfg struct {
	Type              string            `yaml:"type,omitempty"` //file|bin|...
	Mode              string            `yaml:"mode,omitempty"` //tail|cat|...
	Filename          string            `yaml:"filename,omitempty"`
	Filenames         []string          `yaml:"filenames,omitempty"`
	JournalctlFilters []string          `yaml:"journalctl_filter,omitempty"`
	Labels            map[string]string `yaml:"labels,omitempty"`
	Profiling         bool              `yaml:"profiling,omitempty"`
}

type DataSource interface {
	Configure(DataSourceCfg) error
	Exists() (bool, error)
	/*add a type parameter ?*/
	StartTail(chan types.Event, *tomb.Tomb) error
	StartCat(chan types.Event, *tomb.Tomb) error
}

func LoadAcquisitionConfig(config *csconfig.CrowdsecServiceCfg) ([]*DataSource, error) {

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
		/*guess the type of acquisition from the fields*/

	}
	return nil, nil

}
