package setup

import (
	"context"
	"fmt"
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

type testUnitLister struct {Output []string}

func (l testUnitLister) ListUnits(ctx context.Context) ([]string, error) {
	return l.Output, nil
}

type nullProcessLister struct {}

func (nulll nullProcessLister) ListProcesses(ctx context.Context) ([]string, error) {
	return nil, nil
}

func TestPathExists(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	type test struct {
		path string
		want bool
	}

	tests := []test{
		{"/this-should-not-exist", false},
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, test{`C:\`, true})
	} else {
		tests = append(tests, test{"/tmp", true})
	}

	for _, tc := range tests {
		env := NewExprEnvironment(ctx, DetectOptions{}, ExprOS{},
			OSPathChecker{}, testUnitLister{}, nullProcessLister{})

		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			actual := env.PathExists(ctx, tc.path)
			require.Equal(t, tc.want, actual)
		})
	}
}

func TestVersionCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version    string
		constraint string
		want       bool
		wantErr    string
	}{
		{"1", "=1", true, ""},
		{"1", "!=1", false, ""},
		{"1", "<=1", true, ""},
		{"1", ">1", false, ""},
		{"1", ">=1", true, ""},
		{"1.0", "<1.0", false, ""},
		{"1", "<1", false, ""},
		{"1.3.5", "1.3", true, ""},
		{"1.0", "<1.0", false, ""},
		{"1.0", "<=1.0", true, ""},
		{"2", ">1, <3", true, ""},
		{"2", "<=2, >=2.2", false, ""},
		{"2.3", "~2", true, ""},
		{"2.3", "=2", true, ""},
		{"1.1.1", "=1.1", true, ""},
		{"1.1.1", "1.1", true, ""},
		{"1.1", "!=1.1.1", true, ""},
		{"1.1", "~1.1.1", false, ""},
		{"1.1.1", "~1.1", true, ""},
		{"1.1.3", "~1.1", true, ""},
		{"19.04", "<19.10", true, ""},
		{"19.04", ">=19.10", false, ""},
		{"19.04", "=19.4", true, ""},
		{"19.04", "~19.4", true, ""},
		{"1.2.3", "~1.2", true, ""},
		{"1.2.3", "!=1.2", false, ""},
		{"1.2.3", "1.1.1 - 1.3.4", true, ""},
		{"1.3.5", "1.1.1 - 1.3.4", false, ""},
		{"1.3.5", "=1", true, ""},
		{"1.3.5", "1", true, ""},
	}

	for _, tc := range tests {
		e := ExprOS{RawVersion: tc.version}

		t.Run(fmt.Sprintf("Check(%s,%s)", tc.version, tc.constraint), func(t *testing.T) {
			t.Parallel()

			actual, err := e.VersionCheck(tc.constraint)
			cstest.RequireErrorContains(t, err, tc.wantErr)
			require.Equal(t, tc.want, actual)
		})
	}
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
version: 1.0
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
version: 1.0
detect:
	foos:
`,
			nil,
			"yaml: line 4: found character that cannot start any token",
		},
		{
			"invalid yaml: no version",
			"{}",
			nil,
			"missing version tag (must be 1.0)",
		},
		{
			"invalid yaml: bad version",
			"version: 2.0",
			nil,
			"invalid version tag '2.0' (must be 1.0)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewDetector(strings.NewReader(tc.yml))
			cstest.RequireErrorContains(t, err, tc.wantErr)

			if tc.wantErr != "" {
				return
			}

			supported := detector.ListSupportedServices()
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
			"each expression must be a boolan",
			[]string{"true", `"notabool"`},
			false,
			"",
			`rule "\"notabool\"": type must be a boolean`,
		},
		{
			// we keep evaluating expressions to ensure that the
			// file is formally correct, even if it can some time.
			"each expression must be a boolan (no short circuit)",
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

			svc := ServiceRules{When: tc.rules}

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

// XXX TODO: TestEvaluateRules with journalctl default

func TestUnitFound(t *testing.T) {
	ctx := t.Context()

	env := NewExprEnvironment(ctx, DetectOptions{}, ExprOS{}, OSPathChecker{}, testUnitLister{Output: []string{"crowdsec-setup-installed.service"}}, nullProcessLister{})

	installed, err := env.UnitFound(ctx, "crowdsec-setup-installed.service")
	require.NoError(t, err)
	require.True(t, installed)

	installed, err = env.UnitFound(ctx, "crowdsec-setup-missing.service")
	require.NoError(t, err)
	require.False(t, installed)
}

func TestDetectSimpleRule(t *testing.T) {
	ctx := t.Context()

	f := strings.NewReader(`
version: 1.0
detect:
  good:
    when:
      - true
  bad:
    when:
      - false
  ugly:
`)

	detector, err := NewDetector(f)
	require.NoError(t, err)
	got, err := NewSetup(ctx, detector, DetectOptions{},
		OSPathChecker{},
		SystemdUnitLister{},
		GopsutilProcessLister{},
		nullLogger())
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
		name        string
		config      string
		want    *Setup
		wantErr string
	}{
		{
			"detect unit and pick up acquisistion filter",
			`
version: 1.0
detect:
  wizard:
    when:
      - UnitFound("crowdsec-setup-detect.service")
    acquisition:
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

	unitLister := testUnitLister{Output: []string{"crowdsec-setup-detect.service"}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := NewDetector(strings.NewReader(tc.config))
			require.NoError(t, err)
			got, err := NewSetup(ctx, detector, DetectOptions{},
				OSPathChecker{},
				unitLister,
				GopsutilProcessLister{},
				nullLogger())
			cstest.RequireErrorContains(t, err, tc.wantErr)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDetectForcedUnit(t *testing.T) {
	ctx := t.Context()

	f := strings.NewReader(`
version: 1.0
detect:
  wizard:
    when:
      - UnitFound("crowdsec-setup-forced.service")
    acquisition:
      filename: wizard.yaml
      datasource:
        source: journalctl
        labels:
          type: syslog
        journalctl_filter:
          - _SYSTEMD_UNIT=crowdsec-setup-forced.service
`)

	detector, err := NewDetector(f)
	require.NoError(t, err)
	got, err := NewSetup(ctx, detector, DetectOptions{ForcedUnits: []string{"crowdsec-setup-forced.service"}},
				OSPathChecker{},
				SystemdUnitLister{},
				GopsutilProcessLister{},
				nullLogger())
	require.NoError(t, err)

	want := &Setup{
		Plans: []ServicePlan{
			{
				Name: "wizard",
				InstallRecommendation: InstallRecommendation{
					AcquisitionSpec: AcquisitionSpec{
						Filename: "wizard.yaml",
						Datasource: DatasourceConfig{
							"source":            "journalctl",
							"labels":            DatasourceConfig{"type": "syslog"},
							"journalctl_filter": []any{"_SYSTEMD_UNIT=crowdsec-setup-forced.service"},
						},
					},
				},
			},
		},
	}
	require.Equal(t, want, got)
}

func TestDetectForcedProcess(t *testing.T) {
	ctx := t.Context()
	cstest.SkipOnWindows(t)

	f := strings.NewReader(`
version: 1.0
detect:
  wizard:
    when:
      - ProcessRunning("foobar")
`)

	detector, err := NewDetector(f)
	require.NoError(t, err)
	got, err := NewSetup(ctx, detector, DetectOptions{ForcedProcesses: []string{"foobar"}},
		OSPathChecker{},
		SystemdUnitLister{},
		GopsutilProcessLister{},
		nullLogger())
	require.NoError(t, err)

	want := &Setup{
		Plans: []ServicePlan{
			{Name: "wizard"},
		},
	}
	require.Equal(t, want, got)
}

func TestDetectSkipService(t *testing.T) {
	ctx := t.Context()
	cstest.SkipOnWindows(t)

	f := strings.NewReader(`
version: 1.0
detect:
  wizard:
    when:
      - ProcessRunning("foobar")
`)

	detector, err := NewDetector(f)
	require.NoError(t, err)
	got, err := NewSetup(ctx, detector, DetectOptions{ForcedProcesses: []string{"foobar"}, SkipServices: []string{"wizard"}},
		OSPathChecker{},
		SystemdUnitLister{},
		GopsutilProcessLister{},
		nullLogger())
	require.NoError(t, err)

	want := &Setup{[]ServicePlan{}}
	require.Equal(t, want, got)
}

func TestDetectForcedOS(t *testing.T) {
	ctx := t.Context()

	type test struct {
		name        string
		config      string
		forced      ExprOS
		want    *Setup
		wantErr string
	}

	tests := []test{
		{
			"detect OS - force linux",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.Family == "linux"`,
			ExprOS{Family: "linux"},
			&Setup{
				Plans: []ServicePlan{
					{Name: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - force windows",
			`
version: 1.0
detect:
  windows:
    when:
      - OS.Family == "windows"`,
			ExprOS{Family: "windows"},
			&Setup{
				Plans: []ServicePlan{
					{Name: "windows"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu (no match)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.Family == "linux" && OS.ID == "ubuntu"`,
			ExprOS{Family: "linux"},
			&Setup{[]ServicePlan{}},
			"",
		},
		{
			"detect OS - ubuntu (match)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.Family == "linux" && OS.ID == "ubuntu"`,
			ExprOS{Family: "linux", ID: "ubuntu"},
			&Setup{
				Plans: []ServicePlan{
					{Name: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu (match with version)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.Family == "linux" && OS.ID == "ubuntu" && OS.VersionCheck("19.04")`,
			ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.04"},
			&Setup{
				Plans: []ServicePlan{
					{Name: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (no match: no version detected)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			ExprOS{Family: "linux"},
			&Setup{[]ServicePlan{}},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (no match: version is lower)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.10"},
			&Setup{[]ServicePlan{}},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (match: same version)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.04"},
			&Setup{
				Plans: []ServicePlan{
					{Name: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (match: version is higher)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "22.04"},
			&Setup{
				Plans: []ServicePlan{
					{Name: "linux"},
				},
			},
			"",
		},

		{
			"detect OS - ubuntu < 20.04 (no match: no version detected)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu" && OS.VersionCheck("<20.04")`,
			ExprOS{Family: "linux"},
			&Setup{[]ServicePlan{}},
			"",
		},
		{
			"detect OS - ubuntu < 20.04 (no match: version is higher)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu" && OS.VersionCheck("<20.04")`,
			ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.10"},
			&Setup{[]ServicePlan{}},
			"",
		},
		{
			"detect OS - ubuntu < 20.04 (no match: same version)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu" && OS.VersionCheck("<20.04")`,
			ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.04"},
			&Setup{[]ServicePlan{}},
			"",
		},
		{
			"detect OS - ubuntu < 20.04 (match: version is lower)",
			`
version: 1.0
detect:
  linux:
    when:
      - OS.ID == "ubuntu"
      - OS.VersionCheck("<20.04")`,
			ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.10"},
			&Setup{
				Plans: []ServicePlan{
					{Name: "linux"},
				},
			},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := NewDetector(strings.NewReader(tc.config))
			require.NoError(t, err)
			got, err := NewSetup(ctx, detector, DetectOptions{ForcedOS: tc.forced},
				OSPathChecker{},
				SystemdUnitLister{},
				GopsutilProcessLister{},
				nullLogger())
			cstest.RequireErrorContains(t, err, tc.wantErr)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDetectDatasourceValidation(t *testing.T) {
	// It could be a good idea to test UnmarshalConfig() separately in addition
	// to Configure(), in each datasource. For now, we test these here.
	ctx := t.Context()

	type test struct {
		name        string
		config      string
		want    *Setup
		wantErr string
	}

	tests := []test{
		{
			name: "datasource config is missing",
			config: `
version: 1.0
detect:
  wizard:
    acquisition:
      filename: wizard.yaml`,
			want:    nil,
			wantErr: "invalid acquisition spec for wizard: datasource configuration is empty",
		}, {
			name: "datasource config is empty",
			config: `
version: 1.0
detect:
  wizard:
    acquisition:
      filename: wizard.yaml
      datasource: {}`,
			want:    nil,
			wantErr: "invalid acquisition spec for wizard: datasource configuration is empty",
		}, {
			name: "missing acquisition file name",
			config: `
version: 1.0
detect:
  wizard:
    acquisition:
      datasource:
        labels:
          type: something`,
			want:    nil,
			wantErr: "invalid acquisition spec for wizard: a filename for the datasource configuration is mandatory",
		}, {
			name: "source is empty",
			config: `
version: 1.0
detect:
  wizard:
    acquisition:
      filename: something.yaml
      datasource:
        labels:
          type: something`,
			want:    nil,
			wantErr: "invalid acquisition spec for wizard: source is empty",
		}, {
			name: "source is unknown",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: wombat.yaml
      datasource:
        source: wombat`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: unknown data source wombat",
		}, {
			name: "source is misplaced",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: file.yaml
      datasource:
      source: file`,
			want:    nil,
			wantErr: "yaml: unmarshal errors:\n  line 8: field source not found in type setup.AcquisitionSpec",
		}, {
			name: "source is mismatched",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: journalctl.yaml
      datasource:
        source: journalctl
        filename: /path/to/file.log`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: cannot parse JournalCtlSource configuration: yaml: unmarshal errors:\n  line 1: field filename not found in type journalctlacquisition.JournalCtlConfiguration",
		}, {
			name: "source file: required fields",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: file.yaml
      datasource:
        source: file`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: no filename or filenames configuration provided",
		}, {
			name: "source journalctl: required fields",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: foobar.yaml
      datasource:
        source: journalctl`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: journalctl_filter is required",
		}, {
			name: "source cloudwatch: required fields",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: cloudwatch.yaml
      datasource:
        source: cloudwatch`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: group_name is mandatory for CloudwatchSource",
		}, {
			name: "source syslog: all fields are optional",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: syslog.yaml
      datasource:
        source: syslog`,
			want: &Setup{
				Plans: []ServicePlan{
					{
						Name:       "foobar",
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
version: 1.0
detect:
  foobar:
    acquisition:
      filename: docker.yaml
      datasource:
        source: docker`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: no containers names or containers ID configuration provided",
		}, {
			name: "source kinesis: required fields (enhanced fanout=false)",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: kinesis.yaml
      datasource:
        source: kinesis`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: stream_name is mandatory when use_enhanced_fanout is false",
		}, {
			name: "source kinesis: required fields (enhanced fanout=true)",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: kinesis.yaml
      datasource:
        source: kinesis
        use_enhanced_fanout: true`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: stream_arn is mandatory when use_enhanced_fanout is true",
		}, {
			name: "source kafka: required fields",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
      filename: kafka.yaml
      datasource:
        source: kafka`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: cannot create a kafka reader with an empty list of broker addresses",
		}, {
			name: "source loki: required fields",
			config: `
version: 1.0
detect:
  foobar:
    acquisition:
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
version: 1.0
detect:
  foobar:
           acquisition:
             filename: wineventlog.yaml
      datasource:
        source: wineventlog`,
			want:    nil,
			wantErr: "invalid acquisition spec for foobar: event_channel or xpath_query must be set",
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := NewDetector(strings.NewReader(tc.config))
			cstest.RequireErrorContains(t, err, tc.wantErr)

			if tc.wantErr != "" {
				return
			}

			got, err := NewSetup(ctx, detector, DetectOptions{},
				OSPathChecker{},
				SystemdUnitLister{},
				GopsutilProcessLister{},
				nullLogger())
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
