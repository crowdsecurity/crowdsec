package setup_test

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/lithammer/dedent"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/setup"
)

//nolint:dupword
var fakeSystemctlOutput = `UNIT FILE                                 STATE    VENDOR PRESET
crowdsec-setup-detect.service            enabled  enabled
apache2.service                           enabled  enabled
apparmor.service                          enabled  enabled
apport.service                            enabled  enabled
atop.service                              enabled  enabled
atopacct.service                          enabled  enabled
finalrd.service                           enabled  enabled
fwupd-refresh.service                     enabled  enabled
fwupd.service                             enabled  enabled

9 unit files listed.`

func fakeExecCommandNotFound(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestSetupHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command("this-command-does-not-exist", cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

func fakeExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestSetupHelperProcess", "--", command}
	cs = append(cs, args...)
	//nolint:gosec
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

func TestSetupHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	fmt.Fprint(os.Stdout, fakeSystemctlOutput)
	os.Exit(0)
}

func tempYAML(t *testing.T, content string) os.File {
	t.Helper()
	require := require.New(t)
	file, err := os.CreateTemp("", "")
	require.NoError(err)

	_, err = file.WriteString(dedent.Dedent(content))
	require.NoError(err)

	err = file.Close()
	require.NoError(err)

	file, err = os.Open(file.Name())
	require.NoError(err)

	return *file
}

func TestPathExists(t *testing.T) {
	t.Parallel()

	type test struct {
		path     string
		expected bool
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
		tc := tc
		env := setup.NewExprEnvironment(setup.DetectOptions{}, setup.ExprOS{})

		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			actual := env.PathExists(tc.path)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestVersionCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version     string
		constraint  string
		expected    bool
		expectedErr string
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
		tc := tc
		e := setup.ExprOS{RawVersion: tc.version}

		t.Run(fmt.Sprintf("Check(%s,%s)", tc.version, tc.constraint), func(t *testing.T) {
			t.Parallel()
			actual, err := e.VersionCheck(tc.constraint)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.Equal(t, tc.expected, actual)
		})
	}
}

// This is not required for Masterminds/semver
/*
func TestNormalizeVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version  string
		expected string
	}{
		{"0", "0"},
		{"2", "2"},
		{"3.14", "3.14"},
		{"1.0", "1.0"},
		{"18.04", "18.4"},
		{"0.0.0", "0.0.0"},
		{"18.04.0", "18.4.0"},
		{"18.0004.0", "18.4.0"},
		{"21.04.2", "21.4.2"},
		{"050", "50"},
		{"trololo", "trololo"},
		{"0001.002.03", "1.2.3"},
		{"0001.002.03-trololo", "0001.002.03-trololo"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			actual := setup.NormalizeVersion(tc.version)
			require.Equal(t, tc.expected, actual)
		})
	}
}
*/

func TestListSupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		yml         string
		expected    []string
		expectedErr string
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := tempYAML(t, tc.yml)
			defer os.Remove(f.Name())
			supported, err := setup.ListSupported(&f)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.ElementsMatch(t, tc.expected, supported)
		})
	}
}

func TestApplyRules(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tests := []struct {
		name        string
		rules       []string
		expectedOk  bool
		expectedErr string
	}{
		{
			"empty list is always true", // XXX or false?
			[]string{},
			true,
			"",
		},
		{
			"simple true expression",
			[]string{"1+1==2"},
			true,
			"",
		},
		{
			"simple false expression",
			[]string{"2+2==5"},
			false,
			"",
		},
		{
			"all expressions are true",
			[]string{"1+2==3", "1!=2"},
			true,
			"",
		},
		{
			"all expressions must be true",
			[]string{"true", "1==3", "1!=2"},
			false,
			"",
		},
		{
			"each expression must be a boolan",
			[]string{"true", "\"notabool\""},
			false,
			"rule '\"notabool\"': type must be a boolean",
		},
		{
			// we keep evaluating expressions to ensure that the
			// file is formally correct, even if it can some time.
			"each expression must be a boolan (no short circuit)",
			[]string{"false", "3"},
			false,
			"rule '3': type must be a boolean",
		},
		{
			"unknown variable",
			[]string{"false", "doesnotexist"},
			false,
			"rule 'doesnotexist': cannot fetch doesnotexist from",
		},
		{
			"unknown expression",
			[]string{"false", "doesnotexist()"},
			false,
			"rule 'doesnotexist()': cannot fetch doesnotexist from",
		},
	}

	env := setup.ExprEnvironment{}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := setup.Service{When: tc.rules}
			_, actualOk, err := setup.ApplyRules(svc, env) //nolint:typecheck,nolintlint  // exported only for tests
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expectedOk, actualOk)
		})
	}
}

// XXX TODO: TestApplyRules with journalctl default

func TestUnitFound(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	env := setup.NewExprEnvironment(setup.DetectOptions{}, setup.ExprOS{})

	installed, err := env.UnitFound("crowdsec-setup-detect.service")
	require.NoError(err)

	require.Equal(true, installed)
}

// TODO apply rules to filter a list of Service structs
// func testFilterWithRules(t *testing.T) {
// }

func TestDetectSimpleRule(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	f := tempYAML(t, `
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
	defer os.Remove(f.Name())

	detected, err := setup.Detect(&f, setup.DetectOptions{})
	require.NoError(err)

	expected := []setup.ServiceSetup{
		{DetectedService: "good"},
		{DetectedService: "ugly"},
	}

	require.ElementsMatch(expected, detected.Setup)
}

func TestDetectUnitError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	require := require.New(t)
	setup.ExecCommand = fakeExecCommandNotFound

	defer func() { setup.ExecCommand = exec.Command }()

	tests := []struct {
		name        string
		config      string
		expected    setup.Setup
		expectedErr string
	}{
		{
			"error is reported if systemctl does not exist",
			`
version: 1.0
detect:
  wizard:
    when:
      - UnitFound("crowdsec-setup-detect.service")`,
			setup.Setup{[]setup.ServiceSetup{}},
			`while looking for service wizard: rule 'UnitFound("crowdsec-setup-detect.service")': ` +
				`running systemctl: exec: "this-command-does-not-exist": executable file not found in $PATH`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tempYAML(t, tc.config)
			defer os.Remove(f.Name())

			detected, err := setup.Detect(&f, setup.DetectOptions{})
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expected, detected)
		})
	}
}

func TestDetectUnit(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	tests := []struct {
		name        string
		config      string
		expected    setup.Setup
		expectedErr string
	}{
		//		{
		//			"detect a single unit, with default log filter",
		//			`
		// version: 1.0
		// detect:
		//  wizard:
		//    when:
		//      - UnitFound("crowdsec-setup-detect.service")
		//    datasource:
		//      labels:
		//        type: syslog
		//  sorcerer:
		//    when:
		//      - UnitFound("sorcerer.service")`,
		//			setup.Setup{
		//				Setup: []setup.ServiceSetup{
		//					{
		//						DetectedService: "wizard",
		//						DataSource: setup.DataSourceItem{
		//							"Labels":           map[string]string{"type": "syslog"},
		//							"JournalCTLFilter": []string{"_SYSTEMD_UNIT=crowdsec-setup-detect.service"},
		//						},
		//					},
		//				},
		//			},
		//			"",
		//		},
		//		{
		//			"detect a single unit, but type label is missing",
		//			`
		// version: 1.0
		// detect:
		//  wizard:
		//    when:
		//      - UnitFound("crowdsec-setup-detect.service")`,
		//			setup.Setup{},
		//			"missing type label for service wizard",
		//		},
		{
			"detect unit and pick up acquisistion filter",
			`
version: 1.0
detect:
  wizard:
    when:
      - UnitFound("crowdsec-setup-detect.service")
    datasource:
      source: journalctl
      labels:
        type: syslog
      journalctl_filter:
        - _MY_CUSTOM_FILTER=something`,
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{
						DetectedService: "wizard",
						DataSource: setup.DataSourceItem{
							// XXX this should not be DataSourceItem ??
							"source":            "journalctl",
							"labels":            setup.DataSourceItem{"type": "syslog"},
							"journalctl_filter": []interface{}{"_MY_CUSTOM_FILTER=something"},
						},
					},
				},
			},
			"",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tempYAML(t, tc.config)
			defer os.Remove(f.Name())

			detected, err := setup.Detect(&f, setup.DetectOptions{})
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expected, detected)
		})
	}
}

func TestDetectForcedUnit(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	f := tempYAML(t, `
	version: 1.0
	detect:
	  wizard:
	    when:
	      - UnitFound("crowdsec-setup-forced.service")
	    datasource:
	      source: journalctl
	      labels:
	        type: syslog
	      journalctl_filter:
	        - _SYSTEMD_UNIT=crowdsec-setup-forced.service
	`)
	defer os.Remove(f.Name())

	detected, err := setup.Detect(&f, setup.DetectOptions{ForcedUnits: []string{"crowdsec-setup-forced.service"}})
	require.NoError(err)

	expected := setup.Setup{
		Setup: []setup.ServiceSetup{
			{
				DetectedService: "wizard",
				DataSource: setup.DataSourceItem{
					"source":            "journalctl",
					"labels":            setup.DataSourceItem{"type": "syslog"},
					"journalctl_filter": []interface{}{"_SYSTEMD_UNIT=crowdsec-setup-forced.service"},
				},
			},
		},
	}
	require.Equal(expected, detected)
}

func TestDetectForcedProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
		// while looking for service wizard: rule 'ProcessRunning("foobar")': while looking up running processes: could not get Name: A device attached to the system is not functioning.
	}

	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	f := tempYAML(t, `
	version: 1.0
	detect:
	  wizard:
	    when:
	      - ProcessRunning("foobar")
	`)
	defer os.Remove(f.Name())

	detected, err := setup.Detect(&f, setup.DetectOptions{ForcedProcesses: []string{"foobar"}})
	require.NoError(err)

	expected := setup.Setup{
		Setup: []setup.ServiceSetup{
			{DetectedService: "wizard"},
		},
	}
	require.Equal(expected, detected)
}

func TestDetectSkipService(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	f := tempYAML(t, `
	version: 1.0
	detect:
	  wizard:
	    when:
	      - ProcessRunning("foobar")
	`)
	defer os.Remove(f.Name())

	detected, err := setup.Detect(&f, setup.DetectOptions{ForcedProcesses: []string{"foobar"}, SkipServices: []string{"wizard"}})
	require.NoError(err)

	expected := setup.Setup{[]setup.ServiceSetup{}}
	require.Equal(expected, detected)
}

func TestDetectForcedOS(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	type test struct {
		name        string
		config      string
		forced      setup.ExprOS
		expected    setup.Setup
		expectedErr string
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
			setup.ExprOS{Family: "linux"},
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{DetectedService: "linux"},
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
			setup.ExprOS{Family: "windows"},
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{DetectedService: "windows"},
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
			setup.ExprOS{Family: "linux"},
			setup.Setup{[]setup.ServiceSetup{}},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu"},
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{DetectedService: "linux"},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.04"},
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{DetectedService: "linux"},
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
			setup.ExprOS{Family: "linux"},
			setup.Setup{[]setup.ServiceSetup{}},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.10"},
			setup.Setup{[]setup.ServiceSetup{}},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.04"},
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{DetectedService: "linux"},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "22.04"},
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{DetectedService: "linux"},
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
			setup.ExprOS{Family: "linux"},
			setup.Setup{[]setup.ServiceSetup{}},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.10"},
			setup.Setup{[]setup.ServiceSetup{}},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.04"},
			setup.Setup{[]setup.ServiceSetup{}},
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
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.10"},
			setup.Setup{
				Setup: []setup.ServiceSetup{
					{DetectedService: "linux"},
				},
			},
			"",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tempYAML(t, tc.config)
			defer os.Remove(f.Name())

			detected, err := setup.Detect(&f, setup.DetectOptions{ForcedOS: tc.forced})
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expected, detected)
		})
	}
}

func TestDetectDatasourceValidation(t *testing.T) {
	// It could be a good idea to test UnmarshalConfig() separately in addition
	// to Configure(), in each datasource. For now, we test these here.

	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	type test struct {
		name        string
		config      string
		expected    setup.Setup
		expectedErr string
	}

	tests := []test{
		{
			name: "source is empty",
			config: `
				version: 1.0
				detect:
				  wizard:
				    datasource:
				      labels:
				        type: something`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for wizard: source is empty",
		}, {
			name: "source is unknown",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: wombat`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: unknown source 'wombat'",
		}, {
			name: "source is misplaced",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				    source: file`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "yaml: unmarshal errors:\n  line 6: field source not found in type setup.Service",
		}, {
			name: "source is mismatched",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: journalctl
				      filename: /path/to/file.log`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: cannot parse JournalCtlSource configuration: yaml: unmarshal errors:\n  line 1: field filename not found in type journalctlacquisition.JournalCtlConfiguration",
		}, {
			name: "source file: required fields",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: file`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: no filename or filenames configuration provided",
		}, {
			name: "source journalctl: required fields",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: journalctl`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: journalctl_filter is required",
		}, {
			name: "source cloudwatch: required fields",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: cloudwatch`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: group_name is mandatory for CloudwatchSource",
		}, {
			name: "source syslog: all fields are optional",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: syslog`,
			expected: setup.Setup{
				Setup: []setup.ServiceSetup{
					{
						DetectedService: "foobar",
						DataSource:      setup.DataSourceItem{"source": "syslog"},
					},
				},
			},
		}, {
			name: "source docker: required fields",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: docker`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: no containers names or containers ID configuration provided",
		}, {
			name: "source kinesis: required fields (enhanced fanout=false)",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: kinesis`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: stream_name is mandatory when use_enhanced_fanout is false",
		}, {
			name: "source kinesis: required fields (enhanced fanout=true)",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: kinesis
				      use_enhanced_fanout: true`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: stream_arn is mandatory when use_enhanced_fanout is true",
		}, {
			name: "source kafka: required fields",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: kafka`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: cannot create a kafka reader with an empty list of broker addresses",
		}, {
			name: "source loki: required fields",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: loki`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: loki query is mandatory",
		},
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, test{
			name: "source wineventlog: required fields",
			config: `
				version: 1.0
				detect:
				  foobar:
				    datasource:
				      source: wineventlog`,
			expected:    setup.Setup{Setup: []setup.ServiceSetup{}},
			expectedErr: "invalid datasource for foobar: event_channel or xpath_query must be set",
		})
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tempYAML(t, tc.config)
			defer os.Remove(f.Name())
			detected, err := setup.Detect(&f, setup.DetectOptions{})
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expected, detected)
		})
	}
}
