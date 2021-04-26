package acquisition

import (
	"fmt"
	"io"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
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

// The interface each datasource must implement
type DataSource interface {
	Configure([]byte) error                                // Configure the datasource
	Mode() string                                          // Get the mode (TAIL, CAT or SERVER)
	SupportedModes() []string                              // Returns the mode supported by the datasource
	OneShotAcquisition(chan types.Event, *tomb.Tomb) error // Start one shot acquisition(eg, cat a file)
	LiveAcquisition(chan types.Event, *tomb.Tomb) error    // Start live acquisition (eg, tail a file)
}

func DataSourceConfigure(yamlConfig []byte, dataSourceType string) (*DataSource, error) {
	datasourceMap := DataSourceMap{}
	dataSource := datasourceMap.GetDataSource(dataSourceType)
	if dataSource == nil {
		return nil, errors.Errorf("Unknown datasource %s", dataSourceType)
	}
	//dataSourceInstance := *dataSource.New()
	err := dataSource.Configure([]byte(""))

	return dataSource, nil
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
		dec.SetStrict(false)
		for {
			var sub configuration.DataSourceCommonCfg
			err = dec.Decode(&sub)
			if err != nil {
				if err == io.EOF {
					log.Tracef("End of yaml file")
					break
				}
				return nil, errors.Wrap(err, fmt.Sprintf("failed to yaml decode %s", acquisFile))
			}
			// If no type is defined, assume file for backward compatibility
			if sub.Type == "" {
				sub.Type = "file"
			}
			// default mode is tail
			if sub.Mode == "" {
				sub.Mode = configuration.TAIL_MODE
			}
			src, err := DataSourceConfigure([]byte(""), sub.Type)
			if err != nil {
				log.Warningf("while configuring datasource : %s", err)
				continue
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
		AcquisTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis")
			var err error
			if subsrc.Mode() == configuration.TAIL_MODE {
				err = subsrc.LiveAcquisition(output, AcquisTomb)
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
