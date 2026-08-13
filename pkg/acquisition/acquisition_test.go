package acquisition

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/expr-lang/expr"
	"github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tomb "gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	_ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules" // register all datasources
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
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
func appendMockSource(t *testing.T) {
	t.Helper()

	restore := registry.RegisterTestFactory("mock", func() types.DataSource { return &MockSource{} })
	t.Cleanup(restore)
	restore = registry.RegisterTestFactory("mock_cant_run", func() types.DataSource { return &MockSourceCantRun{} })
	t.Cleanup(restore)
}

func TestDataSourceConfigure(t *testing.T) {
	ctx := t.Context()

	appendMockSource(t)

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
			hub := cwhub.Hub{}
			ds, err := DataSourceConfigure(ctx, common, []byte(tc.String), metrics.AcquisitionMetricsLevelNone, &hub)
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
	appendMockSource(t)
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
			ExpectedError: "testdata/missing_labels.yaml: missing labels",
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
			ExpectedError: "testdata/bad_source.yaml: unknown data source does_not_exist",
		},
		{
			TestName: "invalid_filetype_config",
			Config: csconfig.CrowdsecServiceCfg{
				AcquisitionFiles: []string{"testdata/bad_filetype.yaml"},
			},
			ExpectedError: "testdata/bad_filetype.yaml: datasource of type file: cannot parse FileAcquisition configuration: [2:12] string was used where sequence is expected",
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
			hub := cwhub.Hub{}
			dss, err := LoadAcquisitionFromFiles(ctx, &tc.Config, nil, &hub)
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
func (*MockCat) OneShotAcquisition(_ context.Context, out chan pipeline.Event, _ *tomb.Tomb) error {
	for range 10 {
		evt := pipeline.Event{}
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

func (*MockTail) StreamingAcquisition(_ context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	for range 10 {
		evt := pipeline.Event{}
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

// acquisitionTimeout is only ever reached when acquisition fails to terminate:
// it's generous on purpose, a healthy run finishes in microseconds.
const acquisitionTimeout = 10 * time.Second

// quietPeriod is how long we wait to confirm that no extra event shows up. Kept
// short on purpose: an unexpected event slower than this is missed, which is
// better than failing at random on a loaded machine.
const quietPeriod = 100 * time.Millisecond

// startAcquisition starts an acquisition in the background. The returned channel
// receives the result of StartAcquisition, i.e. it fires once the tomb is dead
// and every datasource (and the transformer, if any) is done writing.
func startAcquisition(t *testing.T, sources []types.DataSource, out chan pipeline.Event, acquisTomb *tomb.Tomb) chan error {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- StartAcquisition(t.Context(), sources, out, acquisTomb) }()

	return done
}

// waitForAcquisition waits for acquisition to terminate and returns its error.
func waitForAcquisition(t *testing.T, done chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(acquisitionTimeout):
		t.Fatal("acquisition did not terminate")
		return nil
	}
}

// readEvents reads exactly n events, failing if they don't all show up in time.
func readEvents(t *testing.T, out chan pipeline.Event, n int) []pipeline.Event {
	t.Helper()

	evts := make([]pipeline.Event, 0, n)

	for i := range n {
		select {
		case evt := <-out:
			evts = append(evts, evt)
		case <-time.After(acquisitionTimeout):
			t.Fatalf("timed out waiting for event %d/%d", i+1, n)
		}
	}

	return evts
}

// requireNoMoreEvents checks that acquisition doesn't emit more than expected.
func requireNoMoreEvents(t *testing.T, out chan pipeline.Event) {
	t.Helper()

	select {
	case evt := <-out:
		t.Fatalf("unexpected extra event: %q", evt.Line.Raw)
	case <-time.After(quietPeriod):
	}
}

// runCatAcquisition runs a cat-mode acquisition to completion and returns the raw
// lines it produced. Cat acquisition ends when the tomb dies, i.e. once every
// datasource and the transformer (if any) are done writing, so the result is
// complete and we never have to guess with a sleep.
func runCatAcquisition(t *testing.T, sources []types.DataSource) []string {
	t.Helper()

	// buffered, so nothing can block on writing while we wait for termination
	out := make(chan pipeline.Event, 100)
	acquisTomb := tomb.Tomb{}

	done := startAcquisition(t, sources, out, &acquisTomb)

	if err := waitForAcquisition(t, done); err != nil {
		acquisTomb.Kill(nil)
		require.NoError(t, err)
	}

	got := []string{}
	for len(out) > 0 {
		got = append(got, (<-out).Line.Raw)
	}

	return got
}

func TestStartAcquisitionCat(t *testing.T) {
	got := runCatAcquisition(t, []types.DataSource{&MockCat{}})

	assert.Len(t, got, 10)
}

func TestStartAcquisitionTail(t *testing.T) {
	out := make(chan pipeline.Event, 100)
	acquisTomb := tomb.Tomb{}

	done := startAcquisition(t, []types.DataSource{&MockTail{}}, out, &acquisTomb)

	readEvents(t, out, 10)
	requireNoMoreEvents(t, out)

	// tail mode never ends on its own, so ask it to stop and check that it does
	acquisTomb.Kill(nil)
	require.NoError(t, waitForAcquisition(t, done), "tomb is not dead")
}

type MockTailError struct {
	MockTail
}

func (*MockTailError) StreamingAcquisition(_ context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	for range 10 {
		evt := pipeline.Event{}
		evt.Line.Src = "test"
		out <- evt
	}

	t.Kill(errors.New("got error (tomb)"))

	return errors.New("got error")
}

func TestStartAcquisitionTailError(t *testing.T) {
	// buffered: the datasource kills the tomb right after writing, we read afterwards
	out := make(chan pipeline.Event, 100)
	acquisTomb := tomb.Tomb{}

	done := startAcquisition(t, []types.DataSource{&MockTailError{}}, out, &acquisTomb)

	// the datasource kills the tomb itself, so acquisition ends without our help
	cstest.RequireErrorContains(t, waitForAcquisition(t, done), "got error (tomb)")

	// every write happened before the tomb died, so the events are all buffered
	assert.Len(t, out, 10)
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
			ExpectedError: "baddsn is not a valid dsn (no protocol)",
		},
		{
			dsn:           "foobar://toto",
			ExpectedError: "no acquisition for protocol foobar://",
		},
		{
			dsn:            "mockdsn://test_expect",
		},
		{
			dsn:           "mockdsn://bad",
			ExpectedError: "unexpected value",
		},
	}

	restore := registry.RegisterTestFactory("mockdsn", func() types.DataSource { return &MockSourceByDSN{} })
	t.Cleanup(restore)

	for _, tc := range tests {
		t.Run(tc.dsn, func(t *testing.T) {
			hub := cwhub.Hub{}
			source, err := LoadAcquisitionFromDSN(ctx, tc.dsn, map[string]string{"type": "test_label"}, "", &hub)
			cstest.RequireErrorContains(t, err, tc.ExpectedError)

			if tc.ExpectedError != "" {
				return
			}

			assert.NotNil(t, source)
			assert.Equal(t, "mockdsn", source.GetName())
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
	out := make(chan pipeline.Event)
	errCh := make(chan error, 1)

	var tb tomb.Tomb

	go func() { errCh <- StartAcquisition(ctx, []types.DataSource{&TailModeNoTailer{}}, out, &tb) }()

	require.ErrorContains(t, <-errCh, "tail_no_tailer: tail mode is set but the datasource does not support streaming acquisition")
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
	out := make(chan pipeline.Event)
	errCh := make(chan error, 1)

	var tb tomb.Tomb

	go func() { errCh <- StartAcquisition(ctx, []types.DataSource{&CatModeNoFetcher{}}, out, &tb) }()

	require.ErrorContains(t, <-errCh, "cat_no_fetcher: cat mode is set but OneShotAcquisition is not supported")
}

// MockCatTransform emits a single event in cat mode, and reports a configurable
// uuid so a transform expression can be attached to it.
type MockCatTransform struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	uuid                              string
}

func (*MockCatTransform) UnmarshalConfig(_ []byte) error { return nil }
func (f *MockCatTransform) Configure(_ context.Context, _ []byte, _ *log.Entry, _ metrics.AcquisitionMetricsLevel) error {
	f.Mode = configuration.CAT_MODE
	return nil
}
func (*MockCatTransform) GetMode() string   { return configuration.CAT_MODE }
func (*MockCatTransform) GetName() string   { return "mock_cat_transform" }
func (f *MockCatTransform) GetUuid() string { return f.uuid }
func (f *MockCatTransform) Dump() any       { return f }
func (*MockCatTransform) CanRun() error     { return nil }

func (*MockCatTransform) OneShotAcquisition(_ context.Context, out chan pipeline.Event, _ *tomb.Tomb) error {
	evt := pipeline.Event{}
	evt.Line.Src = "test"
	evt.Line.Raw = "original"
	out <- evt

	return nil
}

// registerTransform compiles expr and attaches it to the given datasource uuid
// for the duration of the test.
func registerTransform(t *testing.T, uuid string, exprStr string) {
	t.Helper()

	prog, err := expr.Compile(exprStr, exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
	require.NoError(t, err)

	transformRuntimes[uuid] = prog

	t.Cleanup(func() { delete(transformRuntimes, uuid) })
}

// TestStartAcquisitionTransform checks that events emitted by a datasource with
// a transform expression actually go through the transformer.
func TestStartAcquisitionTransform(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected []string
	}{
		{
			name:     "string",
			expr:     `evt.Line.Raw + "-transformed"`,
			expected: []string{"original-transformed"},
		},
		{
			name:     "slice",
			expr:     `[evt.Line.Raw + "-1", evt.Line.Raw + "-2"]`,
			expected: []string{"original-1", "original-2"},
		},
		{
			name:     "invalid type, event is sent as-is",
			expr:     `42`,
			expected: []string{"original"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uuid := "transform-" + tc.name

			registerTransform(t, uuid, tc.expr)

			got := runCatAcquisition(t, []types.DataSource{&MockCatTransform{uuid: uuid}})

			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestStartAcquisitionCatTransformTerminates checks that in cat mode, acquisition
// terminates on its own once the datasource is done reading, even when a transform
// is configured. cmd/crowdsec relies on acquisTomb dying to trigger the shutdown.
func TestStartAcquisitionCatTransformTerminates(t *testing.T) {
	uuid := "transform-terminate"

	registerTransform(t, uuid, `evt.Line.Raw + "-transformed"`)

	got := runCatAcquisition(t, []types.DataSource{&MockCatTransform{uuid: uuid}})

	assert.Equal(t, []string{"original-transformed"}, got)
}
