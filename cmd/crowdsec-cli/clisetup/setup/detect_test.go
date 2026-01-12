package setup

import (
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func nullLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	return logger
}

func TestListSupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yml     string
		want    []string
		wantErr string
	}{
		{
			"list configured services",
			`
detect:
  foo:
  bar:
  baz:
`,
			[]string{"foo", "bar", "baz"},
			"",
		},
		{
			"invalid yaml: blahblah",
			"blahblah",
			nil,
			"yaml: unmarshal errors:",
		},
		{
			"invalid yaml: tabs are not allowed",
			`
detect:
	foos:
`,
			nil,
			"yaml: line 3: found character that cannot start any token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detectConfig, err := NewDetectConfig(strings.NewReader(tc.yml))
			cstest.RequireErrorContains(t, err, tc.wantErr)

			if tc.wantErr != "" {
				return
			}

			supported := detectConfig.ListSupportedServices()
			require.ElementsMatch(t, tc.want, supported)
		})
	}
}

func TestEvaluateRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rules          []string
		want           bool
		wantCompileErr string
		wantEvalErr    string
	}{
		{
			"empty list is always true",
			[]string{},
			true,
			"",
			"",
		},
		{
			"simple true expression",
			[]string{"1+1==2"},
			true,
			"",
			"",
		},
		{
			"simple false expression",
			[]string{"2+2==5"},
			false,
			"",
			"",
		},
		{
			"all expressions are true",
			[]string{"1+2==3", "1!=2"},
			true,
			"",
			"",
		},
		{
			"all expressions must be true",
			[]string{"true", "1==3", "1!=2"},
			false,
			"",
			"",
		},
		{
			"each expression must be a boolean",
			[]string{"true", `"notabool"`},
			false,
			"",
			`rule "\"notabool\"": type must be a boolean`,
		},
		{
			// we keep evaluating expressions to ensure that the
			// file is formally correct, even if it can some time.
			"each expression must be a boolean (no short circuit)",
			[]string{"false", "3"},
			false,
			"",
			`rule "3": type must be a boolean`,
		},
		{
			"unknown variable",
			[]string{"false", "doesnotexist"},
			false,
			`compiling rule "doesnotexist": unknown name doesnotexist (1:1)`,
			"",
		},
		{
			"unknown expression",
			[]string{"false", "doesnotexist()"},
			false,
			`compiling rule "doesnotexist()": unknown name doesnotexist (1:1)`,
			"",
		},
	}

	env := &ExprEnvironment{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := ServiceProfile{When: tc.rules}

			err := svc.Compile()
			cstest.RequireErrorContains(t, err, tc.wantCompileErr)

			if tc.wantCompileErr != "" {
				return
			}

			got, err := svc.Evaluate(env, nullLogger())
			cstest.RequireErrorContains(t, err, tc.wantEvalErr)

			if tc.wantEvalErr != "" {
				return
			}

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDetectSimpleRule(t *testing.T) {
	ctx := t.Context()

	f := strings.NewReader(`
detect:
  good:
    when:
      - true
  bad:
    when:
      - false
  ugly:
`)

	detectConfig, err := NewDetectConfig(f)
	require.NoError(t, err)
	got, err := BuildSetup(ctx, detectConfig, DetectOptions{},
		OSExprPath{},
		nil, nil, nullLogger())
	require.NoError(t, err)

	want := []ServicePlan{
		{Name: "good"},
		{Name: "ugly"},
	}

	require.ElementsMatch(t, want, got.Plans)
}

func TestDetectUnit(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name    string
		config  string
		want    *Setup
		wantErr string
	}{
		{
			"detect unit and pick up acquisistion filter",
			`
detect:
  wizard:
    when:
      - Systemd.UnitInstalled("crowdsec-setup-detect.service")
    acquisition_spec:
      filename: wizard.yaml
      datasource:
        source: journalctl
        labels:
          type: syslog
        journalctl_filter:
          - _MY_CUSTOM_FILTER=something`,
			&Setup{
				Plans: []ServicePlan{
					{
						Name: "wizard",
						InstallRecommendation: InstallRecommendation{
							AcquisitionSpec: AcquisitionSpec{
								Filename: "wizard.yaml",
								Datasource: DatasourceConfig{
									"source":            "journalctl",
									"labels":            DatasourceConfig{"type": "syslog"},
									"journalctl_filter": []any{"_MY_CUSTOM_FILTER=something"},
								},
							},
						},
					},
				},
			},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detectConfig, err := NewDetectConfig(strings.NewReader(tc.config))
			require.NoError(t, err)
			got, err := BuildSetup(ctx, detectConfig, DetectOptions{},
				OSExprPath{},
				UnitMap{"crowdsec-setup-detect.service": UnitInfo{}},
				nil, nullLogger())
			cstest.RequireErrorContains(t, err, tc.wantErr)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDetectSkipService(t *testing.T) {
	ctx := t.Context()
	cstest.SkipOnWindows(t)

	f := strings.NewReader(`
detect:
  wizard:
`)

	detectConfig, err := NewDetectConfig(f)
	require.NoError(t, err)

	got, err := BuildSetup(ctx, detectConfig, DetectOptions{},
		OSExprPath{},
		nil, nil, nullLogger())
	require.NoError(t, err)
	require.Len(t, got.Plans, 1)
	require.Equal(t, "wizard", got.Plans[0].Name)

	got, err = BuildSetup(ctx, detectConfig, DetectOptions{SkipServices: []string{"wizard"}},
		OSExprPath{},
		nil, nil, nullLogger())
	require.NoError(t, err)
	require.Empty(t, got.Plans)
}

func TestDetectForceService(t *testing.T) {
	ctx := t.Context()
	cstest.SkipOnWindows(t)

	f := strings.NewReader(`
detect:
  wizard:
    when:
      - System.ProcessRunning("foobar")
`)

	detectConfig, err := NewDetectConfig(f)
	require.NoError(t, err)
	got, err := BuildSetup(ctx, detectConfig, DetectOptions{WantServices: []string{"wizard"}},
		OSExprPath{},
		nil, nil, nullLogger())
	require.NoError(t, err)
	require.Len(t, got.Plans, 1)
	require.Equal(t, "wizard", got.Plans[0].Name)
}

func TestDetectDatasourceValidation(t *testing.T) {
	// It could be a good idea to test UnmarshalConfig() separately in addition
	// to Configure(), in each datasource. For now, we test these here.
	ctx := t.Context()

	type test struct {
		name    string
		config  string
		want    *Setup
		wantErr string
	}

	tests := []test{
		{
			name: "datasource config is missing",
			config: `
detect:
  wizard:
    acquisition_spec:
      filename: wizard.yaml`,
			want:    nil,
			wantErr: "invalid acquisition spec for wizard: datasource configuration is empty",
		}, {
			name: "datasource config is empty",
			config: `
detect:
  wizard:
    acquisition_spec:
      filename: wizard.yaml
      datasource: {}`,
			want:    nil,
			wantErr: "invalid acquisition spec for wizard: datasource configuration is empty",
		}, {
			name: "missing acquisition file name",
			config: `
detect:
  wizard:
    acquisition_spec:
      filename: something.yaml
      datasource:
        labels:
          type: something`,
			want:    nil,
			wantErr: "invalid acquisition spec for wizard: source field is required",
		}, {
			name: "source is unknown",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: wombat.yaml
      datasource:
        source: wombat`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: unknown data source wombat",
		}, {
			name: "source is misplaced",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: file.yaml
      datasource:
      source: file`,
			want:    nil,
			wantErr: "yaml: unmarshal errors:\n  line 7: field source not found in type setup.AcquisitionSpec",
		}, {
			name: "source is mismatched",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: journalctl.yaml
      datasource:
        source: journalctl
        filename: /path/to/file.log`,
			want:    nil,
			wantErr: `invalid acquisition spec for foobar: cannot parse: [1:1] unknown field "filename"`,
		}, {
			name: "source file: required fields",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: file.yaml
      datasource:
        source: file`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: no filename or filenames configuration provided",
		}, {
			name: "source journalctl: required fields",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: foobar.yaml
      datasource:
        source: journalctl`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: journalctl_filter is required",
		}, {
			name: "source cloudwatch: required fields",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: cloudwatch.yaml
      datasource:
        source: cloudwatch`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: group_name is mandatory for CloudwatchSource",
		}, {
			name: "source syslog: all fields are optional",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: syslog.yaml
      datasource:
        source: syslog`,
			want: &Setup{
				Plans: []ServicePlan{
					{
						Name: "foobar",
						InstallRecommendation: InstallRecommendation{
							AcquisitionSpec: AcquisitionSpec{
								Filename: "syslog.yaml",
								Datasource: DatasourceConfig{
									"source": "syslog",
								},
							},
						},
					},
				},
			},
		}, {
			name: "source docker: required fields",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: docker.yaml
      datasource:
        source: docker`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: no containers or services configuration provided",
		}, {
			name: "source kinesis: required fields (enhanced fanout=false)",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: kinesis.yaml
      datasource:
        source: kinesis`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: stream_name is mandatory when use_enhanced_fanout is false",
		}, {
			name: "source kinesis: required fields (enhanced fanout=true)",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: kinesis.yaml
      datasource:
        source: kinesis
        use_enhanced_fanout: true`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: stream_arn is mandatory when use_enhanced_fanout is true",
		}, {
			name: "source kafka: required fields",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: kafka.yaml
      datasource:
        source: kafka`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: cannot create a kafka reader with an empty list of broker addresses",
		}, {
			name: "source loki: required fields",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: loki.yaml
      datasource:
        source: loki`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: loki query is mandatory",
		},
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, test{
			name: "source wineventlog: required fields",
			config: `
detect:
  foobar:
    acquisition_spec:
      filename: wineventlog.yaml
      datasource:
        source: wineventlog`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: event_channel or xpath_query must be set",
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detectConfig, err := NewDetectConfig(strings.NewReader(tc.config))
			cstest.RequireErrorContains(t, err, tc.wantErr)

			if tc.wantErr != "" {
				return
			}

			got, err := BuildSetup(ctx, detectConfig, DetectOptions{},
				OSExprPath{},
				nil, nil, nullLogger())
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
