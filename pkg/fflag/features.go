// Package fflag provides a simple feature flag system.
//
// Feature names are lowercase and can only contain letters, numbers, undercores
// and dots.
//
// good: "foo", "foo_bar", "foo.bar"
// bad: "Foo", "foo-bar"
//
// A feature flag can be enabled by the user with an environment variable
// or by adding it to {ConfigDir}/feature.yaml
//
// I.e. CROWDSEC_FEATURE_FOO_BAR=true
// or in feature.yaml:
// ---
// - foo_bar
//
// If the variable is set to false, the feature can still be enabled
// in feature.yaml. Features cannot be disabled in the file.
//
// A feature flag can be deprecated or retired. A deprecated feature flag is
// still accepted but a warning is logged. A retired feature flag is ignored
// and an error is logged.
//
// A specific deprecation message is used to inform the user of the behavior
// that has been decided when the flag is/was finally retired.
package fflag

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
)

type Feature struct {
	Enabled        bool   // has the user explicitly enabled this feature?
	Deprecated     bool   // Is the feature flag deprecated?
	Retired        bool   // Is the feature flag retired?
	DeprecationMsg string // Why was it deprecated? What happens next? What should the user do?
}

type FeatureMap map[string]Feature

// These are returned by the constructor.
var (
	ErrFeatureNameEmpty   = errors.New("name is empty")
	ErrFeatureNameCase    = errors.New("name is not lowercase")
	ErrFeatureNameInvalid = errors.New("invalid name (allowed a-z, 0-9, _, .)")
)

var ErrFeatureUnknown = errors.New("unknown feature")
var ErrFeatureDeprecated  = errors.New("the flag is deprecated")

func FeatureDeprecatedError(feat Feature) error {
	if feat.DeprecationMsg != "" {
		return fmt.Errorf("%w: %s", ErrFeatureDeprecated, feat.DeprecationMsg)
	}

	return ErrFeatureDeprecated
}

var ErrFeatureRetired = errors.New("the flag is retired")

func FeatureRetiredError(feat Feature) error {
	if feat.DeprecationMsg != "" {
		return fmt.Errorf("%w: %s", ErrFeatureRetired, feat.DeprecationMsg)
	}

	return ErrFeatureRetired
}

var featureNameRexp = regexp.MustCompile(`^[a-z0-9_\.]+$`)

func validateFeatureName(featureName string) error {
	if featureName == "" {
		return ErrFeatureNameEmpty
	}

	if featureName != strings.ToLower(featureName) {
		return ErrFeatureNameCase
	}

	if !featureNameRexp.MatchString(featureName) {
		return ErrFeatureNameInvalid
	}

	return nil
}

func NewFeatureMap(features map[string]Feature) (FeatureMap, error) {
	// XXX should not actually receive a Feature (i.e. Enabled must be false, and
	// it cannot be retired==true && deprecated==false))
	fm := make(FeatureMap)

	for k, v := range features {
		if err := validateFeatureName(k); err != nil {
			return nil, fmt.Errorf("Feature flag '%s': %w", k, err)
		}

		fm[k] = v
	}

	return fm, nil
}

func (fm Feature) IsEnabled() bool {
	return fm.Enabled
}

func (fm FeatureMap) IsFeatureEnabled(featureName string) (bool, error) {
	feat, ok := fm[featureName]
	if !ok {
		return false, ErrFeatureUnknown
	}

	return feat.IsEnabled(), nil
}

func (fm FeatureMap) SetFeature(featureName string, value bool) error {
	feat, ok := fm[featureName]
	if !ok {
		return ErrFeatureUnknown
	}

	// retired feature flags are ignored
	if feat.Retired {
		return FeatureRetiredError(feat)
	}

	feat.Enabled = value
	fm[featureName] = feat

	// deprecated feature flags are still accepted, but a warning is triggered.
	// We return an error but set the feature anyway.
	if feat.Deprecated {
		return FeatureDeprecatedError(feat)
	}

	return nil
}

func (fm FeatureMap) SetFromEnv(prefix string, logger *logrus.Logger) error {
	for _, e := range os.Environ() {
		// ignore non-feature variables
		if !strings.HasPrefix(e, prefix) {
			continue
		}

		// extract feature name and value
		pair := strings.SplitN(e, "=", 2)
		varName := pair[0]
		featureName := strings.ToLower(varName[len(prefix):])
		value := pair[1]

		var enable bool

		switch value {
		case "true":
			enable = true
		case "false":
			enable = false
		default:
			logger.Errorf("Ignored envvar %s=%s: invalid value (must be 'true' or 'false')", varName, value)
			continue
		}

		err := fm.SetFeature(featureName, enable)

		switch {
		case errors.Is(err, ErrFeatureUnknown):
			logger.Errorf("Ignored envvar '%s': %s", varName, err)
			continue
		case errors.Is(err, ErrFeatureRetired):
			logger.Errorf("Ignored envvar '%s': %s", varName, err)
			continue
		case errors.Is(err, ErrFeatureDeprecated):
			logger.Warningf("Envvar '%s': %s", varName, err)
		case err != nil:
			return err
		}

		logger.Infof("Feature flag: %s=%t (from envvar)", featureName, enable)
	}

	return nil
}

func (fm FeatureMap) SetFromYaml(r io.Reader, logger *logrus.Logger) error {
	var cfg []string

	bys, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	// parse config file
	if err := yaml.Unmarshal(bys, &cfg); err != nil {
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to parse feature flags: %w", err)
		}

		logger.Debug("No feature flags in config file")
	}

	// set features
	for _, k := range cfg {
		err := fm.SetFeature(k, true)

		switch {
		case errors.Is(err, ErrFeatureUnknown):
			logger.Errorf("Ignored feature flag '%s': %s", k, err)
			continue
		case errors.Is(err, ErrFeatureRetired):
			logger.Errorf("Ignored feature flag '%s': %s", k, err)
			continue
		case errors.Is(err, ErrFeatureDeprecated):
			logger.Warningf("Feature '%s': %s", k, err)
		case err != nil:
			return err
		}

		logger.Infof("Feature flag: %s=true (from config file)", k)
	}

	return nil
}

func (fm FeatureMap) SetFromYamlFile(path string, logger *logrus.Logger) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debugf("Feature flags config file '%s' does not exist", path)

			return nil
		}

		return fmt.Errorf("failed to open feature flags file: %w", err)
	}
	defer f.Close()

	logger.Debugf("Reading feature flags from %s", path)

	return fm.SetFromYaml(f, logger)
}

// GetEnabledFeatures returns the list of features that have been enabled by the user
func (fm FeatureMap) GetEnabledFeatures() []string {
	ret := make([]string, 0)

	for k := range fm {
		feat := fm[k]
		if feat.IsEnabled() {
			ret = append(ret, k)
		}
	}

	sort.Strings(ret)

	return ret
}
