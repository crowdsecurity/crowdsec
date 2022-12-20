package fflag_test

import (
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Test the constructor, which is not required but useful for validation.
func TestNewFeatureMap(t *testing.T) {
	tests := []struct {
		name        string
		features    map[string]fflag.Feature
		expectedErr string
	}{
		{
			name:     "no feature at all",
			features: map[string]fflag.Feature{},
		},
		{
			name: "a plain feature or two",
			features: map[string]fflag.Feature{
				"plain":          {},
				"plain_version2": {},
			},
		},
		{
			name: "capitalized feature name",
			features: map[string]fflag.Feature{
				"Plain": {},
			},
			expectedErr: "Feature flag 'Plain': name is not lowercase",
		},
		{
			name: "empty feature name",
			features: map[string]fflag.Feature{
				"": {},
			},
			expectedErr: "Feature flag '': name is empty",
		},
		{
			name: "invalid feature name",
			features: map[string]fflag.Feature{
				"meh!": {},
			},
			expectedErr: "Feature flag 'meh!': invalid name (allowed a-z, 0-9, _, .)",
		},
	}

	for _, tc := range tests {
		tc := tc

		t.Run("", func(t *testing.T) {
			_, err := fflag.NewFeatureMap(tc.features)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func setUp(t *testing.T) fflag.FeatureMap {
	t.Helper()

	fm, err := fflag.NewFeatureMap(map[string]fflag.Feature{
		"experimental1":    {},
		"experimental2":    {},
		"bad_idea":         {Deprecated: true},
		"gone_mainstream1": {Deprecated: true},
		"gone_mainstream2": {Deprecated: true},
		"will_be_standard_in_v2": {
			Deprecated:     true,
			DeprecationMsg: "in 2.0 we'll do that by default",
		},
		"was_adopted_in_v1.5": {
			Deprecated:     true,
			Retired:        true,
			DeprecationMsg: "the trinket was implemented in 1.5 with the --funnybunny command line option",
		},
		"was_abandoned_in_v1.5": {
			Deprecated:     true,
			Retired:        true,
			DeprecationMsg: "the magic button didn't work as expected and has been removed in 1.5",
		},
	})
	require.NoError(t, err)

	return fm
}

func TestIsFeatureEnabled(t *testing.T) {
	tests := []struct {
		name        string
		feature     string
		enable      *bool
		expected    bool
		expectedErr string
	}{
		{
			name:     "feature that is disabled by default",
			feature:  "experimental1",
			expected: false,
		}, {
			name:     "enable feature that is disabled by default",
			feature:  "experimental1",
			enable:   types.BoolPtr(true),
			expected: true,
		}, {
			name:        "feature that does not exist",
			feature:     "will_never_exist",
			expectedErr: "unknown feature",
		},
	}

	fm := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.enable != nil {
				err := fm.SetFeature(tc.feature, *tc.enable)
				require.NoError(t, err)
			}

			enabled, err := fm.IsFeatureEnabled(tc.feature)
			cstest.RequireErrorMessage(t, err, tc.expectedErr)
			require.Equal(t, tc.expected, enabled)
		})
	}
}

func TestSetFeature(t *testing.T) {
	tests := []struct {
		name           string // test description
		feature        string // feature name
		value          bool   // value for SetFeature
		expected       bool   // expected value from IsFeatureEnabled
		expectedSetErr string // error expected from SetFeature
		expectedGetErr string // error expected from IsFeatureEnabled
	}{
		{
			name:     "enable a feature to try something new",
			feature:  "experimental1",
			value:    true,
			expected: true,
		}, {
			// not useful in practice, unlikely to happen
			name:     "disable the feature that was enabled",
			feature:  "experimental1",
			value:    false,
			expected: false,
		}, {
			name:           "enable a deprecated feature",
			feature:        "bad_idea",
			value:          true,
			expected:       true,
			expectedSetErr: "the flag is deprecated",
		}, {
			name:           "enable a feature that will be retired in v2",
			feature:        "will_be_standard_in_v2",
			value:          true,
			expected:       true,
			expectedSetErr: "the flag is deprecated: in 2.0 we'll do that by default",
		}, {
			name:     "enable a feature that was retired in v1.5",
			feature:  "was_abandoned_in_v1.5",
			value:    true,
			expected: false,
			expectedSetErr: "the flag is retired: " +
				"the magic button didn't work as expected and has been removed in 1.5",
		}, {
			name:           "enable a feature that does not exist",
			feature:        "will_never_exist",
			value:          true,
			expectedSetErr: "unknown feature",
			expectedGetErr: "unknown feature",
		},
	}

	// we don't instantiate a new feature map for each test, so they are
	// not independent, but it simplifies the test code
	fm := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := fm.SetFeature(tc.feature, tc.value)
			t.Logf("SetFeature(%q, %v) returned %v", tc.feature, tc.value, err)
			cstest.RequireErrorMessage(t, err, tc.expectedSetErr)
			// check that the feature was set, or not
			enabled, err := fm.IsFeatureEnabled(tc.feature)
			cstest.RequireErrorMessage(t, err, tc.expectedGetErr)
			if tc.expectedGetErr != "" {
				return
			}
			require.Equal(t, tc.expected, enabled)
		})
	}
}

func TestSetFromEnv(t *testing.T) {
	tests := []struct {
		name   string
		envvar string
		value  string
		// expected bool
		expectedLog []string
		expectedErr string
	}{
		{
			name:   "variable that does not start with FFLAG_TEST_",
			envvar: "PATH",
			value:  "/bin:/usr/bin/:/usr/local/bin",
			// silently ignored
		}, {
			name:        "enable a feature flag",
			envvar:      "FFLAG_TEST_EXPERIMENTAL1",
			value:       "true",
			expectedLog: []string{"Feature flag: experimental1=true (from envvar)"},
		}, {
			name:        "invalid value (not true or false)",
			envvar:      "FFLAG_TEST_EXPERIMENTAL1",
			value:       "maybe",
			expectedLog: []string{"Ignored envvar FFLAG_TEST_EXPERIMENTAL1=maybe: invalid value (must be 'true' or 'false')"},
		}, {
			name:        "feature flag that is unknown",
			envvar:      "FFLAG_TEST_WILL_NEVER_EXIST",
			value:       "true",
			expectedLog: []string{"Ignored envvar 'FFLAG_TEST_WILL_NEVER_EXIST': unknown feature"},
		}, {
			name:   "enable a deprecated feature",
			envvar: "FFLAG_TEST_BAD_IDEA",
			value:  "true",
			expectedLog: []string{
				"Envvar 'FFLAG_TEST_BAD_IDEA': the flag is deprecated",
				"Feature flag: bad_idea=true (from envvar)",
			},
		}, {
			name:   "enable a feature that was retired in v1.5",
			envvar: "FFLAG_TEST_WAS_ADOPTED_IN_V1.5",
			value:  "true",
			expectedLog: []string{
				"Ignored envvar 'FFLAG_TEST_WAS_ADOPTED_IN_V1.5': the flag is retired: " +
				"the trinket was implemented in 1.5 with the --funnybunny command line option",
			},
		}, {
			// this could happen in theory, but only if environment variables
			// are parsed after configuration files, which is not a good idea
			// because they are more useful asap
			name:   "disable a feature flag already set",
			envvar: "FFLAG_TEST_EXPERIMENTAL1",
			value:  "false",
		},
	}

	fm := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			logger.SetLevel(logrus.InfoLevel)
			t.Setenv(tc.envvar, tc.value)
			err := fm.SetFromEnv("FFLAG_TEST_", logger)
			cstest.RequireErrorMessage(t, err, tc.expectedErr)
			for _, expectedMessage := range tc.expectedLog {
				cstest.RequireLogContains(t, hook, expectedMessage)
			}
		})
	}
}

func TestSetFromYaml(t *testing.T) {
	tests := []struct {
		name        string
		yml         string
		expectedLog []string
		expectedErr string
	}{
		{
			name: "empty file",
			yml:  "",
			// nothing happens
		}, {
			name:        "invalid yaml",
			yml:         "bad! content, bad!",
			expectedErr: "failed to parse feature flags: [1:1] string was used where sequence is expected\n    >  1 | bad! content, bad!\n           ^",
		}, {
			name:        "invalid feature flag name",
			yml:         "- not_a_feature",
			expectedLog: []string{"Ignored feature flag 'not_a_feature': unknown feature"},
		}, {
			name:        "invalid value (must be a list)",
			yml:         "experimental1: true",
			expectedErr: "failed to parse feature flags: [1:14] value was used where sequence is expected\n    >  1 | experimental1: true\n                        ^",
		}, {
			name:        "enable a feature flag",
			yml:         "- experimental1",
			expectedLog: []string{"Feature flag: experimental1=true (from config file)"},
		}, {
			name: "enable a deprecated feature",
			yml:  "- bad_idea",
			expectedLog: []string{
				"Feature 'bad_idea': the flag is deprecated",
				"Feature flag: bad_idea=true (from config file)",
			},
		}, {
			name: "enable a feature that was retired (adopted) in v1.5",
			yml:  "- was_adopted_in_v1.5",
			expectedLog: []string{
				"Ignored feature flag 'was_adopted_in_v1.5': the flag is retired: " +
				"the trinket was implemented in 1.5 with the --funnybunny command line option",
			},
		},
	}

	fm := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			logger.SetLevel(logrus.InfoLevel)
			err := fm.SetFromYaml(strings.NewReader(tc.yml), logger)
			cstest.RequireErrorMessage(t, err, tc.expectedErr)
			for _, expectedMessage := range tc.expectedLog {
				cstest.RequireLogContains(t, hook, expectedMessage)
			}
		})
	}
}

func TestSetFromYamlFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test")
	require.NoError(t, err)

	defer os.Remove(tmpfile.Name())

	// write the config file
	_, err = tmpfile.Write([]byte("- experimental1"))
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	fm := setUp(t)
	logger, hook := logtest.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)

	err = fm.SetFromYamlFile(tmpfile.Name(), logger)
	require.NoError(t, err)

	cstest.RequireLogContains(t, hook, "Feature flag: experimental1=true (from config file)")
}

func TestGetEnabledFeatures(t *testing.T) {
	fm := setUp(t)

	fm.SetFeature("experimental1", true)
	fm.SetFeature("gone_mainstream1", true)
	fm.SetFeature("bad_idea", true)


	expected := []string{
		"bad_idea",
		"experimental1",
		"gone_mainstream1",
	}

	require.Equal(t, expected, fm.GetEnabledFeatures())
}
