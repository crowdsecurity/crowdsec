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

	tomb "gopkg.in/tomb.v2"
)

var ReaderHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_reader_hits_total",
		Help: "Total lines where read.",
	},
	[]string{"source"},
)

/*
 current limits :
 - The acquisition is not yet modular (cf. traefik/yaegi), but we start with an interface to pave the road for it.
 - The configuration item unmarshaled (DataSourceCfg) isn't generic neither yet.
 - This changes should be made when we're ready to have acquisition managed by the hub & cscli
 once this change is done, we might go for the following configuration format instead :
   ```yaml
   ---
   type: nginx
   source: journald
   filter: "PROG=nginx"
   ---
   type: nginx
   source: files
   filenames:
	- "/var/log/nginx/*.log"
	```
*/

/* Approach

We support acquisition in two modes :
 - tail mode : we're following a stream of info (tail -f $src). this is used when monitoring live logs
 - cat mode : we're reading a file/source one-shot (cat $src), and scenarios will match the timestamp extracted from logs.

One DataSourceCfg can lead to multiple goroutines, hence the Tombs passing around to allow proper tracking.
tail mode shouldn't return except on errors or when externally killed via tombs.
cat mode will return once source has been exhausted.


 TBD in current iteration :
  - how to deal with "file was not present at startup but might appear later" ?
*/

var TAIL_MODE = "tail"
var CAT_MODE = "cat"

type DataSourceCfg struct {
	Mode              string            `yaml:"mode,omitempty"` //tail|cat|...
	Filename          string            `yaml:"filename,omitempty"`
	Filenames         []string          `yaml:"filenames,omitempty"`
	JournalctlFilters []string          `yaml:"journalctl_filter,omitempty"`
	Labels            map[string]string `yaml:"labels,omitempty"`
	Profiling         bool              `yaml:"profiling,omitempty"`
}

type DataSource interface {
	Configure(DataSourceCfg) error
	/*the readers must watch the tomb (especially in tail mode) to know when to shutdown.
	tomb is as well used to trigger general shutdown when a datasource errors */
	StartReading(chan types.Event, *tomb.Tomb) error
	Mode() string //return CAT_MODE or TAIL_MODE
	//Not sure it makes sense to make those funcs part of the interface.
	//While 'cat' and 'tail' are the only two modes we see now, other modes might appear
	//StartTail(chan types.Event, *tomb.Tomb) error
	//StartCat(chan types.Event, *tomb.Tomb) error
}

func DataSourceConfigure(config DataSourceCfg) (DataSource, error) {
	if config.Mode == "" { /*default mode is tail*/
		config.Mode = TAIL_MODE
	}

	if len(config.Filename) > 0 || len(config.Filenames) > 0 { /*it's file acquisition*/

		fileSrc := new(FileSource)
		if err := fileSrc.Configure(config); err != nil {
			return nil, errors.Wrap(err, "configuring file datasource")
		}
		return fileSrc, nil
	} else if len(config.JournalctlFilters) > 0 { /*it's journald acquisition*/

		journaldSrc := new(JournaldSource)
		if err := journaldSrc.Configure(config); err != nil {
			return nil, errors.Wrap(err, "configuring journald datasource")
		}
		return journaldSrc, nil
	} else {
		return nil, fmt.Errorf("empty filename(s) and journalctl filter, malformed datasource")
	}
}

func LoadAcquisitionFromFile(config *csconfig.CrowdsecServiceCfg) ([]DataSource, error) {

	var sources []DataSource
	var acquisSources = config.AcquisitionFiles

	for _, acquisFile := range acquisSources {
		log.Infof("loading acquisition file : %s", acquisFile)
		yamlFile, err := os.Open(acquisFile)
		if err != nil {
			return nil, errors.Wrapf(err, "can't open %s", acquisFile)
		}
		dec := yaml.NewDecoder(yamlFile)
		dec.SetStrict(true)
		for {
			sub := DataSourceCfg{}
			err = dec.Decode(&sub)
			if err != nil {
				if err == io.EOF {
					log.Tracef("End of yaml file")
					break
				}
				return nil, errors.Wrap(err, fmt.Sprintf("failed to yaml decode %s", acquisFile))
			}
			src, err := DataSourceConfigure(sub)
			if err != nil {
				log.Warningf("while configuring datasource : %s", err)
				continue
			}
			sources = append(sources, src)
		}
	}

	return sources, nil
}

func StartAcquisition(sources []DataSource, output chan types.Event, AcquisTomb *tomb.Tomb) error {

	for i := 0; i < len(sources); i++ {
		subsrc := sources[i] //ensure its a copy
		log.Debugf("starting one source %d/%d ->> %T", i, len(sources), subsrc)
		AcquisTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis")
			if err := subsrc.StartReading(output, AcquisTomb); err != nil {
				return err
			}
			return nil
		})
	}
	/*return only when acquisition is over (cat) or never (tail)*/
	err := AcquisTomb.Wait()
	return err
}
