package fflag_test

import (
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

func TestRegisterFeature(t *testing.T) {
	tests := []struct {
		name        string
		feature     fflag.Feature
		expectedErr string
	}{
		{
			name: "a plain feature",
			feature: fflag.Feature{
				Name: "plain",
			},
		},
		{
			name: "capitalized feature name",
			feature: fflag.Feature{
				Name: "Plain",
			},
			expectedErr: "feature flag 'Plain': name is not lowercase",
		},
		{
			name: "empty feature name",
			feature: fflag.Feature{
				Name: "",
			},
			expectedErr: "feature flag '': name is empty",
		},
		{
			name: "invalid feature name",
			feature: fflag.Feature{
				Name: "meh!",
			},
			expectedErr: "feature flag 'meh!': invalid name (allowed a-z, 0-9, _, .)",
		},
	}

	for _, tc := range tests {
		tc := tc

		t.Run("", func(t *testing.T) {
			fr := fflag.FeatureRegister{EnvPrefix: "FFLAG_TEST_"}
			err := fr.RegisterFeature(&tc.feature)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func setUp(t *testing.T) fflag.FeatureRegister {
	t.Helper()

	fr := fflag.FeatureRegister{EnvPrefix: "FFLAG_TEST_"}

	err := fr.RegisterFeature(&fflag.Feature{Name: "experimental1"})
	require.NoError(t, err)

	err = fr.RegisterFeature(&fflag.Feature{
		Name:        "some_feature",
		Description: "A feature that does something, with a description",
	})
	require.NoError(t, err)

	err = fr.RegisterFeature(&fflag.Feature{
		Name:           "new_standard",
		State:          fflag.DeprecatedState,
		Description:    "This implements the new standard T34.256w",
		DeprecationMsg: "In 2.0 we'll do T34.256w by default",
	})
	require.NoError(t, err)

	err = fr.RegisterFeature(&fflag.Feature{
		Name:           "was_adopted",
		State:          fflag.RetiredState,
		Description:    "This implements a new tricket",
		DeprecationMsg: "The trinket was implemented in 1.5",
	})
	require.NoError(t, err)

	return fr
}

func TestGetFeature(t *testing.T) {
	tests := []struct {
		name        string
		feature     string
		expectedErr string
	}{
		{
			name:    "just a feature",
			feature: "experimental1",
		}, {
			name:        "feature that does not exist",
			feature:     "will_never_exist",
			expectedErr: "unknown feature",
		},
	}

	fr := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := fr.GetFeature(tc.feature)
			cstest.RequireErrorMessage(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}
		})
	}
}

func TestIsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		feature  string
		enable   bool
		expected bool
	}{
		{
			name:     "feature that was not enabled",
			feature:  "experimental1",
			expected: false,
		}, {
			name:     "feature that was enabled",
			feature:  "experimental1",
			enable:   true,
			expected: true,
		},
	}

	fr := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			feat, err := fr.GetFeature(tc.feature)
			require.NoError(t, err)

			err = feat.Set(tc.enable)
			require.NoError(t, err)

			require.Equal(t, tc.expected, feat.IsEnabled())
		})
	}
}

func TestFeatureSet(t *testing.T) {
	tests := []struct {
		name           string // test description
		feature        string // feature name
		value          bool   // value for SetFeature
		expected       bool   // expected value from IsEnabled
		expectedSetErr string // error expected from SetFeature
		expectedGetErr string // error expected from GetFeature
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
			name:           "enable a feature that will be retired in v2",
			feature:        "new_standard",
			value:          true,
			expected:       true,
			expectedSetErr: "the flag is deprecated",
		}, {
			name:           "enable a feature that was retired in v1.5",
			feature:        "was_adopted",
			value:          true,
			expected:       false,
			expectedSetErr: "the flag is retired",
		}, {
			name:           "enable a feature that does not exist",
			feature:        "will_never_exist",
			value:          true,
			expectedSetErr: "unknown feature",
			expectedGetErr: "unknown feature",
		},
	}

	// the tests are not indepedent because we don't instantiate a feature
	// map for each one, but it simplified the code
	fr := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			feat, err := fr.GetFeature(tc.feature)
			cstest.RequireErrorMessage(t, err, tc.expectedGetErr)
			if tc.expectedGetErr != "" {
				return
			}

			err = feat.Set(tc.value)
			cstest.RequireErrorMessage(t, err, tc.expectedSetErr)
			require.Equal(t, tc.expected, feat.IsEnabled())
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
			name:   "enable a feature flag with a description",
			envvar: "FFLAG_TEST_SOME_FEATURE",
			value:  "true",
			expectedLog: []string{
				"Feature flag: some_feature=true (from envvar). A feature that does something, with a description",
			},
		}, {
			name:   "enable a deprecated feature",
			envvar: "FFLAG_TEST_NEW_STANDARD",
			value:  "true",
			expectedLog: []string{
				"Envvar 'FFLAG_TEST_NEW_STANDARD': the flag is deprecated. In 2.0 we'll do T34.256w by default",
				"Feature flag: new_standard=true (from envvar). This implements the new standard T34.256w",
			},
		}, {
			name:   "enable a feature that was retired in v1.5",
			envvar: "FFLAG_TEST_WAS_ADOPTED",
			value:  "true",
			expectedLog: []string{
				"Ignored envvar 'FFLAG_TEST_WAS_ADOPTED': the flag is retired. " +
					"The trinket was implemented in 1.5",
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

	fr := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			logger.SetLevel(logrus.DebugLevel)
			t.Setenv(tc.envvar, tc.value)
			err := fr.SetFromEnv(logger)
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
			// no error
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
			yml:  "- new_standard",
			expectedLog: []string{
				"Feature 'new_standard': the flag is deprecated. In 2.0 we'll do T34.256w by default",
				"Feature flag: new_standard=true (from config file). This implements the new standard T34.256w",
			},
		}, {
			name: "enable a retired feature",
			yml:  "- was_adopted",
			expectedLog: []string{
				"Ignored feature flag 'was_adopted': the flag is retired. The trinket was implemented in 1.5",
			},
		},
	}

	fr := setUp(t)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			logger.SetLevel(logrus.DebugLevel)
			err := fr.SetFromYaml(strings.NewReader(tc.yml), logger)
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
	_, err = tmpfile.WriteString("- experimental1")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	fr := setUp(t)
	logger, hook := logtest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)

	err = fr.SetFromYamlFile(tmpfile.Name(), logger)
	require.NoError(t, err)

	cstest.RequireLogContains(t, hook, "Feature flag: experimental1=true (from config file)")
}

func TestGetEnabledFeatures(t *testing.T) {
	fr := setUp(t)

	feat1, err := fr.GetFeature("new_standard")
	require.NoError(t, err)
	feat1.Set(true)

	feat2, err := fr.GetFeature("experimental1")
	require.NoError(t, err)
	feat2.Set(true)

	expected := []string{
		"experimental1",
		"new_standard",
	}

	require.Equal(t, expected, fr.GetEnabledFeatures())
}
