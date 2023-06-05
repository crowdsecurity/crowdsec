package acquisition

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type MockSource struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	Toto                              string `yaml:"toto"`
	logger                            *log.Entry
}

func (f *MockSource) UnmarshalConfig(cfg []byte) error {
	err := yaml.UnmarshalStrict(cfg, &f)
	if err != nil {
		return err
	}

	return nil
}

func (f *MockSource) Configure(cfg []byte, logger *log.Entry) error {
	f.logger = logger
	if err := f.UnmarshalConfig(cfg); err != nil {
		return err
	}
	if f.Mode == "" {
		f.Mode = configuration.CAT_MODE
	}
	if f.Mode != configuration.CAT_MODE && f.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("mode %s is not supported", f.Mode)
	}
	if f.Toto == "" {
		return fmt.Errorf("expect non-empty toto")
	}
	return nil
}
func (f *MockSource) GetMode() string                                         { return f.Mode }
func (f *MockSource) OneShotAcquisition(chan types.Event, *tomb.Tomb) error   { return nil }
func (f *MockSource) StreamingAcquisition(chan types.Event, *tomb.Tomb) error { return nil }
func (f *MockSource) CanRun() error                                           { return nil }
func (f *MockSource) GetMetrics() []prometheus.Collector                      { return nil }
func (f *MockSource) GetAggregMetrics() []prometheus.Collector                { return nil }
func (f *MockSource) Dump() interface{}                                       { return f }
func (f *MockSource) GetName() string                                         { return "mock" }
func (f *MockSource) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("not supported")
}
func (f *MockSource) GetUuid() string { return "" }

// copy the mocksource, but this one can't run
type MockSourceCantRun struct {
	MockSource
}

func (f *MockSourceCantRun) CanRun() error   { return fmt.Errorf("can't run bro") }
func (f *MockSourceCantRun) GetName() string { return "mock_cant_run" }

// appendMockSource is only used to add mock source for tests
func appendMockSource() {
	if GetDataSourceIface("mock") == nil {
		AcquisitionSources["mock"] = func() DataSource { return &MockSource{} }
	}
	if GetDataSourceIface("mock_cant_run") == nil {
		AcquisitionSources["mock_cant_run"] = func() DataSource { return &MockSourceCantRun{} }
	}
}

func TestDataSourceConfigure(t *testing.T) {
	appendMockSource()
	tests := []struct {
		TestName      string
		String        string
		ExpectedError string
	}{
		{
			TestName: "basic_valid_config",
			String: `
mode: cat
labels:
  test: foobar
log_level: info
source: mock
toto: test_value1
`,
		},
		{
			TestName: "basic_debug_config",
			String: `
mode: cat
labels:
  test: foobar
log_level: debug
source: mock
toto: test_value1
`,
		},
		{
			TestName: "basic_tailmode_config",
			String: `
mode: tail
labels:
  test: foobar
log_level: debug
source: mock
toto: test_value1
`,
		},
		{
			TestName: "bad_mode_config",
			String: `
mode: ratata
labels:
  test: foobar
log_level: debug
source: mock
toto: test_value1
`,
			ExpectedError: "failed to configure datasource mock: mode ratata is not supported",
		},
		{
			TestName: "bad_type_config",
			String: `
mode: cat
labels:
  test: foobar
log_level: debug
source: tutu
`,
			ExpectedError: "cannot find source tutu",
		},
		{
			TestName: "mismatch_config",
			String: `
mode: cat
labels:
  test: foobar
log_level: debug
source: mock
wowo: ajsajasjas
`,
			ExpectedError: "field wowo not found in type acquisition.MockSource",
		},
		{
			TestName: "cant_run_error",
			String: `
mode: cat
labels:
  test: foobar
log_level: debug
source: mock_cant_run
wowo: ajsajasjas
`,
			ExpectedError: "datasource mock_cant_run cannot be run: can't run bro",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.TestName, func(t *testing.T) {
			common := configuration.DataSourceCommonCfg{}
			yaml.Unmarshal([]byte(tc.String), &common)
			ds, err := DataSourceConfigure(common)
			cstest.RequireErrorContains(t, err, tc.ExpectedError)
			if tc.ExpectedError != "" {
				return
			}

			switch tc.TestName {
			case "basic_valid_config":
				mock := (*ds).Dump().(*MockSource)
				assert.Equal(t, mock.Toto, "test_value1")
				assert.Equal(t, mock.Mode, "cat")
				assert.Equal(t, mock.logger.Logger.Level, log.InfoLevel)
				assert.Equal(t, mock.Labels, map[string]string{"test": "foobar"})
			case "basic_debug_config":
				mock := (*ds).Dump().(*MockSource)
				assert.Equal(t, mock.Toto, "test_value1")
				assert.Equal(t, mock.Mode, "cat")
				assert.Equal(t, mock.logger.Logger.Level, log.DebugLevel)
				assert.Equal(t, mock.Labels, map[string]string{"test": "foobar"})
			case "basic_tailmode_config":
				mock := (*ds).Dump().(*MockSource)
				assert.Equal(t, mock.Toto, "test_value1")
				assert.Equal(t, mock.Mode, "tail")
				assert.Equal(t, mock.logger.Logger.Level, log.DebugLevel)
				assert.Equal(t, mock.Labels, map[string]string{"test": "foobar"})
			}
		})
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
			ExpectedError: "open does_not_exist: " + cstest.FileNotFoundMessage,
			ExpectedLen:   0,
		},
		{
			TestName: "invalid_yaml_file",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/badyaml.yaml"},
			},
			ExpectedError: "failed to yaml decode test_files/badyaml.yaml: yaml: unmarshal errors",
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
		{
			TestName: "missing_labels",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/missing_labels.yaml"},
			},
			ExpectedError: "missing labels in test_files/missing_labels.yaml",
		},
		{
			TestName: "backward_compat",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/backward_compat.yaml"},
			},
			ExpectedLen: 2,
		},
		{
			TestName: "bad_type",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/bad_source.yaml"},
			},
			ExpectedError: "unknown data source does_not_exist in test_files/bad_source.yaml",
		},
		{
			TestName: "invalid_filetype_config",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"test_files/bad_filetype.yaml"},
			},
			ExpectedError: "while configuring datasource of type file from test_files/bad_filetype.yaml",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.TestName, func(t *testing.T) {
			dss, err := LoadAcquisitionFromFile(&tc.Config)
			cstest.RequireErrorContains(t, err, tc.ExpectedError)
			if tc.ExpectedError != "" {
				return
			}

			assert.Len(t, dss, tc.ExpectedLen)
		})

	}
}

/*
 test start acquisition :
  - create mock parser in cat mode : start acquisition, check it returns, count items in chan
  - create mock parser in tail mode : start acquisition, sleep, check item count, tomb kill it, wait for it to return
*/

type MockCat struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	logger                            *log.Entry
}

func (f *MockCat) Configure(cfg []byte, logger *log.Entry) error {
	f.logger = logger
	if f.Mode == "" {
		f.Mode = configuration.CAT_MODE
	}
	if f.Mode != configuration.CAT_MODE {
		return fmt.Errorf("mode %s is not supported", f.Mode)
	}
	return nil
}

func (f *MockCat) UnmarshalConfig(cfg []byte) error { return nil }
func (f *MockCat) GetName() string                  { return "mock_cat" }
func (f *MockCat) GetMode() string                  { return "cat" }
func (f *MockCat) OneShotAcquisition(out chan types.Event, tomb *tomb.Tomb) error {
	for i := 0; i < 10; i++ {
		evt := types.Event{}
		evt.Line.Src = "test"
		out <- evt
	}
	return nil
}
func (f *MockCat) StreamingAcquisition(chan types.Event, *tomb.Tomb) error {
	return fmt.Errorf("can't run in tail")
}
func (f *MockCat) CanRun() error                            { return nil }
func (f *MockCat) GetMetrics() []prometheus.Collector       { return nil }
func (f *MockCat) GetAggregMetrics() []prometheus.Collector { return nil }
func (f *MockCat) Dump() interface{}                        { return f }
func (f *MockCat) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("not supported")
}
func (f *MockCat) GetUuid() string { return "" }

//----

type MockTail struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	logger                            *log.Entry
}

func (f *MockTail) Configure(cfg []byte, logger *log.Entry) error {
	f.logger = logger
	if f.Mode == "" {
		f.Mode = configuration.TAIL_MODE
	}
	if f.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("mode %s is not supported", f.Mode)
	}
	return nil
}

func (f *MockTail) UnmarshalConfig(cfg []byte) error { return nil }
func (f *MockTail) GetName() string                  { return "mock_tail" }
func (f *MockTail) GetMode() string                  { return "tail" }
func (f *MockTail) OneShotAcquisition(out chan types.Event, tomb *tomb.Tomb) error {
	return fmt.Errorf("can't run in cat mode")
}
func (f *MockTail) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	for i := 0; i < 10; i++ {
		evt := types.Event{}
		evt.Line.Src = "test"
		out <- evt
	}
	<-t.Dying()
	return nil
}
func (f *MockTail) CanRun() error                            { return nil }
func (f *MockTail) GetMetrics() []prometheus.Collector       { return nil }
func (f *MockTail) GetAggregMetrics() []prometheus.Collector { return nil }
func (f *MockTail) Dump() interface{}                        { return f }
func (f *MockTail) ConfigureByDSN(string, map[string]string, *log.Entry, string) error {
	return fmt.Errorf("not supported")
}
func (f *MockTail) GetUuid() string { return "" }

//func StartAcquisition(sources []DataSource, output chan types.Event, AcquisTomb *tomb.Tomb) error {

func TestStartAcquisitionCat(t *testing.T) {
	sources := []DataSource{
		&MockCat{},
	}
	out := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	go func() {
		if err := StartAcquisition(sources, out, &acquisTomb); err != nil {
			t.Errorf("unexpected error")
		}
	}()

	count := 0
READLOOP:
	for {
		select {
		case <-out:
			count++
		case <-time.After(1 * time.Second):
			break READLOOP
		}
	}

	assert.Equal(t, 10, count)
}

func TestStartAcquisitionTail(t *testing.T) {
	sources := []DataSource{
		&MockTail{},
	}
	out := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	go func() {
		if err := StartAcquisition(sources, out, &acquisTomb); err != nil {
			t.Errorf("unexpected error")
		}
	}()

	count := 0
READLOOP:
	for {
		select {
		case <-out:
			count++
		case <-time.After(1 * time.Second):
			break READLOOP
		}
	}

	assert.Equal(t, 10, count)

	acquisTomb.Kill(nil)
	time.Sleep(1 * time.Second)
	require.NoError(t, acquisTomb.Err(), "tomb is not dead")
}

type MockTailError struct {
	MockTail
}

func (f *MockTailError) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	for i := 0; i < 10; i++ {
		evt := types.Event{}
		evt.Line.Src = "test"
		out <- evt
	}
	t.Kill(fmt.Errorf("got error (tomb)"))
	return fmt.Errorf("got error")
}

func TestStartAcquisitionTailError(t *testing.T) {
	sources := []DataSource{
		&MockTailError{},
	}
	out := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	go func() {
		if err := StartAcquisition(sources, out, &acquisTomb); err != nil && err.Error() != "got error (tomb)" {
			t.Errorf("expected error, got '%s'", err)
		}
	}()

	count := 0
READLOOP:
	for {
		select {
		case <-out:
			count++
		case <-time.After(1 * time.Second):
			break READLOOP
		}
	}
	assert.Equal(t, 10, count)
	//acquisTomb.Kill(nil)
	time.Sleep(1 * time.Second)
	cstest.RequireErrorContains(t, acquisTomb.Err(), "got error (tomb)")
}

type MockSourceByDSN struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	Toto                              string     `yaml:"toto"`
	logger                            *log.Entry //nolint: unused
}

func (f *MockSourceByDSN) UnmarshalConfig(cfg []byte) error                        { return nil }
func (f *MockSourceByDSN) Configure(cfg []byte, logger *log.Entry) error           { return nil }
func (f *MockSourceByDSN) GetMode() string                                         { return f.Mode }
func (f *MockSourceByDSN) OneShotAcquisition(chan types.Event, *tomb.Tomb) error   { return nil }
func (f *MockSourceByDSN) StreamingAcquisition(chan types.Event, *tomb.Tomb) error { return nil }
func (f *MockSourceByDSN) CanRun() error                                           { return nil }
func (f *MockSourceByDSN) GetMetrics() []prometheus.Collector                      { return nil }
func (f *MockSourceByDSN) GetAggregMetrics() []prometheus.Collector                { return nil }
func (f *MockSourceByDSN) Dump() interface{}                                       { return f }
func (f *MockSourceByDSN) GetName() string                                         { return "mockdsn" }
func (f *MockSourceByDSN) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	dsn = strings.TrimPrefix(dsn, "mockdsn://")
	if dsn != "test_expect" {
		return fmt.Errorf("unexpected value")
	}
	return nil
}
func (f *MockSourceByDSN) GetUuid() string { return "" }

func TestConfigureByDSN(t *testing.T) {
	tests := []struct {
		dsn            string
		ExpectedError  string
		ExpectedResLen int
	}{
		{
			dsn:           "baddsn",
			ExpectedError: "baddsn isn't valid dsn (no protocol)",
		},
		{
			dsn:           "foobar://toto",
			ExpectedError: "no acquisition for protocol foobar://",
		},
		{
			dsn:            "mockdsn://test_expect",
			ExpectedResLen: 1,
		},
		{
			dsn:           "mockdsn://bad",
			ExpectedError: "unexpected value",
		},
	}

	if GetDataSourceIface("mockdsn") == nil {
		AcquisitionSources["mockdsn"] = func() DataSource { return &MockSourceByDSN{} }
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.dsn, func(t *testing.T) {
			srcs, err := LoadAcquisitionFromDSN(tc.dsn, map[string]string{"type": "test_label"}, "")
			cstest.RequireErrorContains(t, err, tc.ExpectedError)

			assert.Len(t, srcs, tc.ExpectedResLen)
		})
	}
}
