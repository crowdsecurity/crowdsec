package acquisition

import (
	"fmt"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type MockSource struct {
	configuration.DataSourceCommonCfg
	logger *log.Entry `yaml:"-"`
	Toto   string     `yaml:"toto"`
}

func (f *MockSource) GetMetrics() []prometheus.Collector {
	return nil
}
func (f *MockSource) Configure(cfg []byte, logger *log.Entry) error {
	f.logger = logger
	f.logger.Infof("config called, bytes: %s", string(cfg))
	f.logger.Tracef("this is trace!")

	if err := yaml.Unmarshal(cfg, f); err != nil {
		return errors.Wrap(err, "while unmarshaling to reader specific config")
	}
	if f.Toto == "" {
		return fmt.Errorf("expect non-empty toto")
	}
	return nil
}
func (f *MockSource) GetMode() string {
	f.logger.Debugf("called")
	return f.Mode
}
func (f *MockSource) SupportedModes() []string {
	return []string{"tail", "cat"}
}
func (f *MockSource) OneShotAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (f *MockSource) LiveAcquisition(chan types.Event, *tomb.Tomb) error {
	return nil
}

func (f *MockSource) CanRun() error {
	return nil
}

//appendMockSource is only used to add mock source for tests
func appendMockSource() {
	if GetDataSourceIface("mock") == nil {
		mock := struct {
			name  string
			iface DataSource
		}{name: "mock", iface: &MockSource{}}
		AcquisitionSources = append(AcquisitionSources, mock)
	}
}

func TestLoadAcquisition(t *testing.T) {

	appendMockSource()

	config := []byte(
		`
mode: tail
labels:
  toto: tutu
type: mock
toto: foobar
log_level: trace
`)
	var generic interface{}
	var common configuration.DataSourceCommonCfg

	if err := yaml.Unmarshal(config, &generic); err != nil {
		t.Fatalf("failed to unmarshal %s : %s", config, err)
	}

	outBytes, err := yaml.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("-> %s", outBytes)

	if err := yaml.Unmarshal(outBytes, &common); err != nil {
		t.Fatalf("cannot unmarshal to generic : %s", err)
	}

	// if generic == nil {
	// 	t.Fatalf("result of unmarshal is empty :(")
	// }
	// log.Printf("raw iface : %s", spew.Sdump(generic))
	// common = generic.(configuration.DataSourceCommonCfg)

	ds, err := DataSourceConfigure(outBytes, common)
	log.Printf("-> ds : %s", spew.Sdump(ds))
	log.Printf("-> err : %s", err)
}
