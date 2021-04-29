package acquisition

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
	"gotest.tools/v3/assert"
)

type MockSource struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	Toto                              string `yaml:"toto"`
	logger                            *log.Entry
}

func (f *MockSource) Configure(cfg []byte, logger *log.Entry) error {
	f.logger = logger
	if err := yaml.UnmarshalStrict(cfg, &f); err != nil {
		return errors.Wrap(err, "while unmarshaling to reader specific config")
	}
	if f.Toto == "" {
		return fmt.Errorf("expect non-empty toto")
	}
	return nil
}
func (f *MockSource) GetMode() string                                       { return f.Mode }
func (f *MockSource) SupportedModes() []string                              { return []string{"tail", "cat"} }
func (f *MockSource) OneShotAcquisition(chan types.Event, *tomb.Tomb) error { return nil }
func (f *MockSource) LiveAcquisition(chan types.Event, *tomb.Tomb) error    { return nil }
func (f *MockSource) CanRun() error                                         { return nil }
func (f *MockSource) GetMetrics() []prometheus.Collector                    { return nil }
func (f *MockSource) Dump() interface{}                                     { return f }

//func (f *MockSource) New() DataSource                                       { return &MockSource{} }

//copy the mocksource, but this one can't run
type MockSourceCantRun struct {
	MockSource
}

func (f *MockSourceCantRun) CanRun() error   { return fmt.Errorf("can't run bro") }
func (f *MockSourceCantRun) New() DataSource { return &MockSourceCantRun{} }

//appendMockSource is only used to add mock source for tests
func appendMockSource() {
	if GetDataSourceIface("mock") == nil {
		mock := struct {
			name  string
			iface func() DataSource
		}{
			name:  "mock",
			iface: func() DataSource { return &MockSource{} },
		}
		AcquisitionSources = append(AcquisitionSources, mock)
	}
	if GetDataSourceIface("mock_cant_run") == nil {
		mock := struct {
			name  string
			iface func() DataSource
		}{
			name:  "mock_cant_run",
			iface: func() DataSource { return &MockSourceCantRun{} },
		}
		AcquisitionSources = append(AcquisitionSources, mock)
	}
}

func TestDataSourceConfigure(t *testing.T) {
	appendMockSource()
	tests := []struct {
		TestName      string
		RawBytes      []byte
		ExpectedError string
	}{
		{
			TestName: "basic_valid_config",
			RawBytes: []byte(`
mode: cat
labels:
  test: foobar
log_level: info
type: mock
toto: test_value1
`),
		},
		{
			TestName: "basic_debug_config",
			RawBytes: []byte(`
mode: cat
labels:
  test: foobar
log_level: debug
type: mock
toto: test_value1
`),
		},
		{
			TestName: "basic_tailmode_config",
			RawBytes: []byte(`
mode: tail
labels:
  test: foobar
log_level: debug
type: mock
toto: test_value1
`),
		},
		{
			TestName: "bad_mode_config",
			RawBytes: []byte(`
mode: ratata
labels:
  test: foobar
log_level: debug
type: mock
toto: test_value1
`),
			ExpectedError: "ratata mode is not supported by mock",
		},
		{
			TestName: "bad_type_config",
			RawBytes: []byte(`
mode: ratata
labels:
  test: foobar
log_level: debug
type: tutu
`),
			ExpectedError: "cannot find source tutu",
		},
		{
			TestName: "mismatch_config",
			RawBytes: []byte(`
mode: cat
labels:
  test: foobar
log_level: debug
type: mock
wowo: ajsajasjas
`),
			ExpectedError: "field wowo not found in type acquisition.MockSource",
		},
		{
			TestName: "cant_run_error",
			RawBytes: []byte(`
mode: cat
labels:
  test: foobar
log_level: debug
type: mock_cant_run
wowo: ajsajasjas
`),
			ExpectedError: "datasource mock_cant_run cannot be run: can't run bro",
		},
	}

	for _, test := range tests {
		common := configuration.DataSourceCommonCfg{}
		yaml.Unmarshal(test.RawBytes, &common)
		ds, err := DataSourceConfigure(test.RawBytes, common)
		if test.ExpectedError != "" {
			if err == nil {
				t.Fatalf("expected error %s, got none", test.ExpectedError)
			}
			if !strings.Contains(err.Error(), test.ExpectedError) {
				t.Fatalf("%s : expected error '%s' in '%s'", test.TestName, test.ExpectedError, err.Error())
			} else {
				continue
			}
		} else {
			if err != nil {
				t.Fatalf("%s : unexpected error '%s'", test.TestName, err)
			}
		}

		switch test.TestName {
		case "basic_valid_config":
			mock := (*ds).Dump().(*MockSource)
			assert.Equal(t, mock.Toto, "test_value1")
			assert.Equal(t, mock.Mode, "cat")
			assert.Equal(t, mock.logger.Logger.Level, log.InfoLevel)
			assert.DeepEqual(t, mock.Labels, map[string]string{"test": "foobar"})
		case "basic_debug_config":
			mock := (*ds).Dump().(*MockSource)
			assert.Equal(t, mock.Toto, "test_value1")
			assert.Equal(t, mock.Mode, "cat")
			assert.Equal(t, mock.logger.Logger.Level, log.DebugLevel)
			assert.DeepEqual(t, mock.Labels, map[string]string{"test": "foobar"})
		case "basic_tailmode_config":
			mock := (*ds).Dump().(*MockSource)
			assert.Equal(t, mock.Toto, "test_value1")
			assert.Equal(t, mock.Mode, "tail")
			assert.Equal(t, mock.logger.Logger.Level, log.DebugLevel)
			assert.DeepEqual(t, mock.Labels, map[string]string{"test": "foobar"})
		}
	}
}

func TestLoadAcquisitionFromFile(t *testing.T) {
	appendMockSource()
	tests := []struct {
		TestName      string
		Config        csconfig.CrowdsecServiceCfg
		ExpectedError string
		ExpectedLen   int
	}{
		{
			TestName: "non_existent_file",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"does_not_exist"},
			},
			ExpectedError: "can't open does_not_exist",
			ExpectedLen:   0,
		},
		{
			TestName: "invalid_yaml_file",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/badyaml.yaml"},
			},
			ExpectedError: "configuration isn't valid config in test_files/badyaml.yaml",
			ExpectedLen:   0,
		},
		{
			TestName: "invalid_empty_yaml",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/emptyitem.yaml"},
			},
			ExpectedLen: 0,
		},
		{
			TestName: "basic_valid",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/basic_filemode.yaml"},
			},
			ExpectedLen: 2,
		},
	}
	for _, test := range tests {
		dss, err := LoadAcquisitionFromFile(&test.Config)
		if test.ExpectedError != "" {
			if err == nil {
				t.Fatalf("expected error %s, got none", test.ExpectedError)
			}
			if !strings.Contains(err.Error(), test.ExpectedError) {
				t.Fatalf("%s : expected error '%s' in '%s'", test.TestName, test.ExpectedError, err.Error())
			} else {
				continue
			}
		} else {
			if err != nil {
				t.Fatalf("%s : unexpected error '%s'", test.TestName, err)
			}
		}
		if len(dss) != test.ExpectedLen {
			t.Fatalf("%s : expected %d datasources got %d", test.TestName, test.ExpectedLen, len(dss))
		}

	}
}
