package acquisition

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tomb "gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type MockSource struct {
	Toto                              string `yaml:"toto"`
	logger                            *log.Entry
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

func (f *MockSource) UnmarshalConfig(cfg []byte) error {
	err := yaml.UnmarshalWithOptions(cfg, f, yaml.Strict())
	if err != nil {
		return errors.New(yaml.FormatError(err, false, false))
	}

	return nil
}

func (f *MockSource) Configure(_ context.Context, cfg []byte, logger *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
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
		return errors.New("expect non-empty toto")
	}

	return nil
}
func (f *MockSource) GetMode() string { return f.Mode }
func (*MockSource) CanRun() error     { return nil }
func (f *MockSource) Dump() any       { return f }
func (*MockSource) GetName() string   { return "mock" }
func (*MockSource) GetUuid() string   { return "" }

// copy the mocksource, but this one can't run
type MockSourceCantRun struct {
	MockSource
}

func (*MockSourceCantRun) CanRun() error   { return errors.New("can't run bro") }
func (*MockSourceCantRun) GetName() string { return "mock_cant_run" }

// appendMockSource is only used to add mock source for tests.
func appendMockSource() {
	AcquisitionSources["mock"] = func() DataSource { return &MockSource{} }
	AcquisitionSources["mock_cant_run"] = func() DataSource { return &MockSourceCantRun{} }
}

func TestDataSourceConfigure(t *testing.T) {
	ctx := t.Context()

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
			ExpectedError: "mode ratata is not supported",
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
			ExpectedError: "unknown data source tutu",
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
			ExpectedError: `[7:1] unknown field "wowo"`,
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
			ExpectedError: "datasource 'mock_cant_run' is not available: can't run bro",
		},
		{
			TestName: "empty common section -- bypassing source autodetect",
			String: `
filename: foo.log
`,
			ExpectedError: "data source type is empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.TestName, func(t *testing.T) {
			common := configuration.DataSourceCommonCfg{}
			err := yaml.Unmarshal([]byte(tc.String), &common)
			require.NoError(t, err)
			ds, err := DataSourceConfigure(ctx, common, []byte(tc.String), metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(t, err, tc.ExpectedError)

			if tc.ExpectedError != "" {
				return
			}

			switch tc.TestName {
			case "basic_valid_config":
				mock := ds.Dump().(*MockSource)
				assert.Equal(t, "test_value1", mock.Toto)
				assert.Equal(t, "cat", mock.Mode)
				assert.Equal(t, log.InfoLevel, mock.logger.Logger.Level)
				assert.Equal(t, map[string]string{"test": "foobar"}, mock.Labels)
			case "basic_debug_config":
				mock := ds.Dump().(*MockSource)
				assert.Equal(t, "test_value1", mock.Toto)
				assert.Equal(t, "cat", mock.Mode)
				assert.Equal(t, log.DebugLevel, mock.logger.Logger.Level)
				assert.Equal(t, map[string]string{"test": "foobar"}, mock.Labels)
			case "basic_tailmode_config":
				mock := ds.Dump().(*MockSource)
				assert.Equal(t, "test_value1", mock.Toto)
				assert.Equal(t, "tail", mock.Mode)
				assert.Equal(t, log.DebugLevel, mock.logger.Logger.Level)
				assert.Equal(t, map[string]string{"test": "foobar"}, mock.Labels)
			}
		})
	}
}

func TestLoadAcquisitionFromFiles(t *testing.T) {
	appendMockSource()
	t.Setenv("TEST_ENV", "test_value2")

	ctx := t.Context()

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
				AcquisitionFiles: []string{"testdata/badyaml.yaml"},
			},
			ExpectedError: "[1:1] string was used where mapping is expected",
			ExpectedLen:   0,
		},
		{
			TestName: "invalid_empty_yaml",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/emptyitem.yaml"},
			},
			ExpectedLen: 0,
		},
		{
			TestName: "basic_valid",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/basic_filemode.yaml"},
			},
			ExpectedLen: 2,
		},
		{
			TestName: "missing_labels",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/missing_labels.yaml"},
			},
			ExpectedError: "missing labels in testdata/missing_labels.yaml",
		},
		{
			TestName: "backward_compat",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/backward_compat.yaml"},
			},
			ExpectedLen: 2,
		},
		{
			TestName: "bad_type",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/bad_source.yaml"},
			},
			ExpectedError: "in file testdata/bad_source.yaml (position 0) - unknown data source does_not_exist",
		},
		{
			TestName: "invalid_filetype_config",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/bad_filetype.yaml"},
			},
			ExpectedError: "while configuring datasource of type file from testdata/bad_filetype.yaml",
		},
		{
			TestName: "from_env",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/env.yaml"},
			},
			ExpectedLen: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.TestName, func(t *testing.T) {
			dss, err := LoadAcquisitionFromFiles(ctx, &tc.Config, nil)
			cstest.RequireErrorContains(t, err, tc.ExpectedError)

			if tc.ExpectedError != "" {
				return
			}

			assert.Len(t, dss, tc.ExpectedLen)

			if tc.TestName == "from_env" {
				mock := dss[0].Dump().(*MockSource)
				assert.Equal(t, "test_value2", mock.Toto)
				assert.Equal(t, "foobar", mock.Labels["test"])
				assert.Equal(t, "${NON_EXISTING}", mock.Labels["non_existing"])
				assert.Equal(t, log.InfoLevel, mock.logger.Logger.Level)
			}
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
}

func (f *MockCat) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	if f.Mode == "" {
		f.Mode = configuration.CAT_MODE
	}

	if f.Mode != configuration.CAT_MODE {
		return fmt.Errorf("mode %s is not supported", f.Mode)
	}

	return nil
}

func (*MockCat) UnmarshalConfig(_ []byte) error { return nil }
func (*MockCat) GetName() string                { return "mock_cat" }
func (*MockCat) GetMode() string                { return "cat" }
func (*MockCat) OneShotAcquisition(_ context.Context, out chan types.Event, _ *tomb.Tomb) error {
	for range 10 {
		evt := types.Event{}
		evt.Line.Src = "test"
		out <- evt
	}

	return nil
}

func (*MockCat) CanRun() error   { return nil }
func (f *MockCat) Dump() any     { return f }
func (*MockCat) GetUuid() string { return "" }

// ----

type MockTail struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

func (f *MockTail) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	if f.Mode == "" {
		f.Mode = configuration.TAIL_MODE
	}

	if f.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("mode %s is not supported", f.Mode)
	}

	return nil
}

func (*MockTail) UnmarshalConfig(_ []byte) error { return nil }
func (*MockTail) GetName() string                { return "mock_tail" }
func (*MockTail) GetMode() string                { return "tail" }

func (*MockTail) StreamingAcquisition(_ context.Context, out chan types.Event, t *tomb.Tomb) error {
	for range 10 {
		evt := types.Event{}
		evt.Line.Src = "test"
		out <- evt
	}

	<-t.Dying()

	return nil
}
func (*MockTail) CanRun() error   { return nil }
func (f *MockTail) Dump() any     { return f }
func (*MockTail) GetUuid() string { return "" }

// func StartAcquisition(sources []DataSource, output chan types.Event, AcquisTomb *tomb.Tomb) error {

func TestStartAcquisitionCat(t *testing.T) {
	ctx := t.Context()
	sources := []DataSource{
		&MockCat{},
	}
	out := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	go func() {
		if err := StartAcquisition(ctx, sources, out, &acquisTomb); err != nil {
			t.Error("unexpected error")
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
	ctx := t.Context()
	sources := []DataSource{
		&MockTail{},
	}
	out := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	go func() {
		if err := StartAcquisition(ctx, sources, out, &acquisTomb); err != nil {
			t.Error("unexpected error")
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

func (*MockTailError) StreamingAcquisition(_ context.Context, out chan types.Event, t *tomb.Tomb) error {
	for range 10 {
		evt := types.Event{}
		evt.Line.Src = "test"
		out <- evt
	}

	t.Kill(errors.New("got error (tomb)"))

	return errors.New("got error")
}

func TestStartAcquisitionTailError(t *testing.T) {
	ctx := t.Context()
	sources := []DataSource{
		&MockTailError{},
	}
	out := make(chan types.Event)
	acquisTomb := tomb.Tomb{}

	go func() {
		if err := StartAcquisition(ctx, sources, out, &acquisTomb); err != nil && err.Error() != "got error (tomb)" {
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
	// acquisTomb.Kill(nil)
	time.Sleep(1 * time.Second)
	cstest.RequireErrorContains(t, acquisTomb.Err(), "got error (tomb)")
}

type MockSourceByDSN struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	Toto                              string `yaml:"toto"`
	logger                            *log.Entry //nolint:unused
}

func (*MockSourceByDSN) UnmarshalConfig(_ []byte) error { return nil }
func (*MockSourceByDSN) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	return nil
}
func (f *MockSourceByDSN) GetMode() string { return f.Mode }
func (*MockSourceByDSN) CanRun() error     { return nil }
func (f *MockSourceByDSN) Dump() any       { return f }
func (*MockSourceByDSN) GetName() string   { return "mockdsn" }
func (*MockSourceByDSN) ConfigureByDSN(_ context.Context, dsn string, _ map[string]string, _ *log.Entry, _ string) error {
	dsn = strings.TrimPrefix(dsn, "mockdsn://")
	if dsn != "test_expect" {
		return errors.New("unexpected value")
	}

	return nil
}
func (*MockSourceByDSN) GetUuid() string { return "" }

func TestConfigureByDSN(t *testing.T) {
	ctx := t.Context()

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

	AcquisitionSources["mockdsn"] = func() DataSource { return &MockSourceByDSN{} }

	for _, tc := range tests {
		t.Run(tc.dsn, func(t *testing.T) {
			srcs, err := LoadAcquisitionFromDSN(ctx, tc.dsn, map[string]string{"type": "test_label"}, "")
			cstest.RequireErrorContains(t, err, tc.ExpectedError)

			assert.Len(t, srcs, tc.ExpectedResLen)
		})
	}
}


// TailModeNoTailer configures itself in "tail" mode but does not implement the Tailer methods.
type TailModeNoTailer struct {}
func (*TailModeNoTailer) UnmarshalConfig(_ []byte) error { return nil }
func (*TailModeNoTailer) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error { return nil }
func (*TailModeNoTailer) GetMode() string   { return configuration.TAIL_MODE }
func (*TailModeNoTailer) GetName() string   { return "tail_no_tailer" }
func (*TailModeNoTailer) GetUuid() string   { return "" }
func (s *TailModeNoTailer) Dump() any       { return s }
func (*TailModeNoTailer) CanRun() error     { return nil }

func TestStartAcquisition_MissingTailer(t *testing.T) {
	ctx := t.Context()
	out := make(chan types.Event)
	errCh := make(chan error, 1)

	var tb tomb.Tomb

	go func() { errCh <- StartAcquisition(ctx, []DataSource{&TailModeNoTailer{}}, out, &tb) }()

	require.ErrorContains(t, <-errCh, "tail_no_tailer: tail mode is set but StreamingAcquisition is not supported")
}


// CatModeNoTailer configures itself in "cat" mode but does not implement the Fetcher methods.
type CatModeNoFetcher struct {}
func (*CatModeNoFetcher) UnmarshalConfig(_ []byte) error { return nil }
func (*CatModeNoFetcher) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error { return nil }
func (*CatModeNoFetcher) GetMode() string { return configuration.CAT_MODE }
func (*CatModeNoFetcher) GetName() string { return "cat_no_fetcher" }
func (*CatModeNoFetcher) GetUuid() string { return "" }
func (s *CatModeNoFetcher) Dump() any       { return s }
func (*CatModeNoFetcher) CanRun() error   { return nil }

func TestStartAcquisition_MissingFetcher(t *testing.T) {
	ctx := t.Context()
	out := make(chan types.Event)
	errCh := make(chan error, 1)

	var tb tomb.Tomb

	go func() { errCh <- StartAcquisition(ctx, []DataSource{&CatModeNoFetcher{}}, out, &tb) }()

	require.ErrorContains(t, <-errCh, "cat_no_fetcher: cat mode is set but OneShotAcquisition is not supported")
}
