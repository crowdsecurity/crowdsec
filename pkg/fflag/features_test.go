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
		"may_contain_nuts": {DefaultEnabled: true},
		"bad_idea":         {DefaultEnabled: false, Deprecated: true},
		"gone_mainstream1": {DefaultEnabled: true, Deprecated: true},
		"gone_mainstream2": {DefaultEnabled: true, Deprecated: true},
		"will_be_standard_in_v2": {
			DefaultEnabled: false,
			Deprecated:     true,
			DeprecationMsg: "in 2.0 we'll do that by default",
		},
		"will_be_abandoned_in_v2": {
			DefaultEnabled: false,
			Deprecated:     true,
			DeprecationMsg: "in 2.0 we'll have a better way to do it",
		},
		"was_adopted_in_v1.5": {
			DefaultEnabled: true,
			Deprecated:     true,
			Retired:        true,
			DeprecationMsg: "the trinket was implemented in 1.5 with the --funnybunny command line option",
		},
		"was_abandoned_in_v1.5": {
			DefaultEnabled: false,
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
			name:     "feature that is enabled by default",
			feature:  "may_contain_nuts",
			expected: true,
		}, {
			name:     "disable feature that is enabled by default",
			feature:  "may_contain_nuts",
			enable:   types.BoolPtr(false),
			expected: false,
		}, {
			name:        "feature that does not exist",
			feature:     "will_never_exist",
			expectedErr: "Feature flag 'will_never_exist': unknown feature flag",
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
			name:     "can set the same feature twice with the same value",
			feature:  "experimental1",
			value:    true,
			expected: true,
		}, {
			name:           "can't set the same feature again with a different value",
			feature:        "experimental1",
			value:          false,
			expected:       true,
			expectedSetErr: "Feature flag 'experimental1': feature is already set to true",
		}, {
			name:     "disable an experimental feature, explicitly",
			feature:  "experimental2",
			value:    false,
			expected: false,
		}, {
			name:     "disable a mainstream feature that is causing problems",
			feature:  "may_contain_nuts",
			value:    false,
			expected: false,
		}, {
			name:           "enable a deprecated feature which defaults to false",
			feature:        "bad_idea",
			value:          true,
			expected:       true,
			expectedSetErr: "Feature flag 'bad_idea': the flag is deprecated",
		}, {
			name:           "enable a deprecated feature which defaults to true",
			feature:        "gone_mainstream1",
			value:          true,
			expected:       true,
			expectedSetErr: "Feature flag 'gone_mainstream1': the flag is deprecated",
		}, {
			name:           "disable a deprecated feature which defaults to true",
			feature:        "gone_mainstream2",
			value:          false,
			expected:       false,
			expectedSetErr: "Feature flag 'gone_mainstream2': the flag is deprecated",
		}, {
			name:           "enable a feature that will be retired in v2, default true",
			feature:        "will_be_standard_in_v2",
			value:          true,
			expected:       true,
			expectedSetErr: "Feature flag 'will_be_standard_in_v2': the flag is deprecated: in 2.0 we'll do that by default",
		}, {
			name:           "enable a feature that will be retired in v2, default false",
			feature:        "will_be_abandoned_in_v2",
			value:          true,
			expected:       true,
			expectedSetErr: "Feature flag 'will_be_abandoned_in_v2': the flag is deprecated: in 2.0 we'll have a better way to do it",
		}, {
			name:     "enable a feature that was retired in v1.5, default true",
			feature:  "was_adopted_in_v1.5",
			value:    true,
			expected: true,
			expectedSetErr: "Feature flag 'was_adopted_in_v1.5': the flag is deprecated: " +
				"the trinket was implemented in 1.5 with the --funnybunny command line option",
		}, {
			name:     "enable a feature that was retired in v1.5, default false",
			feature:  "was_abandoned_in_v1.5",
			value:    true,
			expected: false,
			expectedSetErr: "Feature flag 'was_abandoned_in_v1.5': the flag is deprecated: " +
				"the magic button didn't work as expected and has been removed in 1.5",
		}, {
			name:           "enable a feature that does not exist",
			feature:        "will_never_exist",
			value:          true,
			expectedSetErr: "Feature flag 'will_never_exist': unknown feature flag",
			expectedGetErr: "Feature flag 'will_never_exist': unknown feature flag",
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
			expectedLog: []string{"Enabled feature 'experimental1' with envvar 'FFLAG_TEST_EXPERIMENTAL1'"},
		}, {
			name:        "invalid value (not true or false)",
			envvar:      "FFLAG_TEST_EXPERIMENTAL1",
			value:       "maybe",
			expectedLog: []string{"Ignored envvar FFLAG_TEST_EXPERIMENTAL1=maybe: invalid value (must be 'true' or 'false')"},
		}, {
			name:        "feature flag that is unknown",
			envvar:      "FFLAG_TEST_WILL_NEVER_EXIST",
			value:       "true",
			expectedLog: []string{"Ignored envvar 'FFLAG_TEST_WILL_NEVER_EXIST': Feature flag 'will_never_exist': unknown feature"},
		}, {
			name:   "enable a deprecated feature",
			envvar: "FFLAG_TEST_BAD_IDEA",
			value:  "true",
			expectedLog: []string{
				"Envvar 'FFLAG_TEST_BAD_IDEA': Feature flag 'bad_idea': the flag is deprecated",
				"Enabled feature 'bad_idea' with envvar 'FFLAG_TEST_BAD_IDEA'",
			},
		}, {
			name:   "enable a feature that was retired (adopted) in v1.5",
			envvar: "FFLAG_TEST_WAS_ADOPTED_IN_V1.5",
			value:  "true",
			expectedLog: []string{
				"Envvar 'FFLAG_TEST_WAS_ADOPTED_IN_V1.5': Feature flag 'was_adopted_in_v1.5': " +
					"the flag is deprecated: the trinket was implemented in 1.5 with the --funnybunny " +
					"command line option",
			},
		}, {
			// this is unlikely to happen, because environment
			// variables are prioritized over the config file
			name:   "enable a feature flag already set",
			envvar: "FFLAG_TEST_EXPERIMENTAL1",
			value:  "false",
			expectedLog: []string{
				"Ignored envvar 'FFLAG_TEST_EXPERIMENTAL1': Feature flag 'experimental1': feature is already set to true",
			},
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
			expectedErr: "failed to parse feature flags: [1:1] string was used where mapping is expected\n    >  1 | bad! content, bad!\n           ^",
		}, {
			name:        "invalid feature flag name",
			yml:         "not_a_feature: true",
			expectedLog: []string{"Ignored feature 'not_a_feature': Feature flag 'not_a_feature': unknown feature flag"},
		}, {
			name:        "invalid value (not true or false)",
			yml:         "experimental1: maybe",
			expectedErr: "failed to parse feature flags: [1:16] cannot unmarshal string into Go value of type bool\n    >  1 | experimental1: maybe\n                          ^",
		}, {
			name:        "enable a feature flag",
			yml:         "experimental1: true",
			expectedLog: []string{"Enabled feature 'experimental1' with config file"},
		}, {
			name: "enable a deprecated feature",
			yml:  "bad_idea: true",
			expectedLog: []string{
				"Feature flag 'bad_idea': the flag is deprecated",
				"Enabled feature 'bad_idea' with config file",
			},
		}, {
			name: "enable a feature that was retired (adopted) in v1.5",
			yml:  "was_adopted_in_v1.5: true",
			expectedLog: []string{
				"Feature flag 'was_adopted_in_v1.5': the flag is deprecated: " +
					"the trinket was implemented in 1.5 with the --funnybunny command line option",
			},
		}, {
			name: "enable a feature flag already set",
			yml:  "experimental1: false",
			expectedLog: []string{
				"Feature flag 'experimental1': feature is already set to true",
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
	_, err = tmpfile.Write([]byte("experimental1: true"))
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	fm := setUp(t)
	logger, hook := logtest.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)

	err = fm.SetFromYamlFile(tmpfile.Name(), logger)
	require.NoError(t, err)

	cstest.RequireLogContains(t, hook, "Enabled feature 'experimental1' with config file")
}

func TestGetFeatureStatus(t *testing.T) {
	fm := setUp(t)
	status, err := fm.GetFeatureStatus()
	require.NoError(t, err)

	expected := map[string]bool{
		"bad_idea":                false,
		"experimental1":           false,
		"experimental2":           false,
		"gone_mainstream1":        true,
		"gone_mainstream2":        true,
		"may_contain_nuts":        true,
		"was_abandoned_in_v1.5":   false,
		"was_adopted_in_v1.5":     true,
		"will_be_abandoned_in_v2": false,
		"will_be_standard_in_v2":  false,
	}

	require.Equal(t, expected, status)
}
