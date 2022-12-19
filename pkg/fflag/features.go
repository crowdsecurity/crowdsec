// Package fflag provides a simple feature flag system.
//
// Feature names are lowercase and can only contain letters, numbers, undercores
// and dots.
//
// good: "foo", "foo_bar", "foo.bar"
// bad: "Foo", "foo-bar"
//
// A feature flag can be enabled or disabled. It can also be deprecated or
// retired. A deprecated feature flag is still accepted but a warning is
// logged. A retired feature flag is ignored and an error is logged.
//
// Feature flags can be set from environment variables or from a config file.
//
// I.e. CROWDSEC_FEATURE_FOO_BAR=true
// or in features.yaml:
// ---
// foo_bar: true
//
// If a feature flag is set from both, the first one that is parsed (usually
// environment variables) takes precedence. If the value in the second one
// does not match the value already set, an error is logged. This is done
// to highlight inconsistencies in the configuration.
package fflag

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
)

type Feature struct {
	UserEnabled    *bool  // has the user explicitly enabled/disabled this feature?
	DefaultEnabled bool   // Default value of the feature flag.
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

var (
	ErrFeatureUnknown      = errors.New("unknown feature flag")
	ErrFeatureDeprecated   = errors.New("the flag is deprecated")
	ErrFeatureInvalidValue = errors.New("invalid value (must be 'true' or 'false')")
	ErrFeatureAlreadySet   = errors.New("feature is already set")
)

func FeatureDeprecatedError(feat Feature) error {
	if feat.DeprecationMsg != "" {
		return fmt.Errorf("%w: %s", ErrFeatureDeprecated, feat.DeprecationMsg)
	}

	return ErrFeatureDeprecated
}

var ErrFeatureRetired = errors.New("the flag has been retired")

func FeatureRetiredError(feat Feature) error {
	if feat.DeprecationMsg != "" {
		return fmt.Errorf("%w: %s", ErrFeatureDeprecated, feat.DeprecationMsg)
	}

	return ErrFeatureDeprecated
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
	// XXX should not actually receive a Feature (i.e. Enabled must be nil, and
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

func (fm FeatureMap) IsFeatureEnabled(featureName string) (bool, error) {
	feat, ok := fm[featureName]
	if !ok {
		return false, fmt.Errorf("Feature flag '%s': %w", featureName, ErrFeatureUnknown)
	}

	if feat.UserEnabled != nil {
		return *feat.UserEnabled, nil
	}

	return feat.DefaultEnabled, nil
}

func (fm FeatureMap) SetFeature(featureName string, value bool) error {
	var ret error

	feat, ok := fm[featureName]
	if !ok {
		return fmt.Errorf("Feature flag '%s': %w", featureName, ErrFeatureUnknown)
	}

	// retired feature flags are ignored
	if feat.Retired {
		return fmt.Errorf("Feature flag '%s': %w", featureName, FeatureRetiredError(feat))
	}

	// deprecated feature flags are still accepted, but a warning is triggered.
	// We return an error but set the feature anyway.
	if feat.Deprecated {
		ret = fmt.Errorf("Feature flag '%s': %w", featureName, FeatureDeprecatedError(feat))
	}

	// return error if the feature flag has been set with a different value
	// (i.e. enabled by environment variable and disabled in config file, the
	// environment variable takes precedence)
	if feat.UserEnabled != nil && *feat.UserEnabled != value {
		return fmt.Errorf("Feature flag '%s': %w to %t", featureName, ErrFeatureAlreadySet, *feat.UserEnabled)
	}

	feat.UserEnabled = &value
	fm[featureName] = feat

	return ret
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
			logger.Errorf("Ignored envvar %s=%s: %v", varName, value, ErrFeatureInvalidValue)
			continue
		}

		err := fm.SetFeature(featureName, enable)

		switch {
		case errors.Is(err, ErrFeatureUnknown):
			logger.Errorf("Ignored envvar '%s': %s", varName, err)
			continue
		case errors.Is(err, ErrFeatureDeprecated):
			logger.Warningf("Envvar '%s': %s", varName, err)
		case errors.Is(err, ErrFeatureRetired):
			logger.Errorf("Ignored envvar '%s': %s", varName, err)
			continue
		case errors.Is(err, ErrFeatureAlreadySet):
			logger.Warningf("Ignored envvar '%s': %s", varName, err)
			continue
		case err != nil:
			return err
		}

		if enable {
			logger.Infof("Enabled feature '%s' with envvar '%s'", featureName, varName)
		} else {
			logger.Infof("Disabled feature '%s' with envvar '%s'", featureName, varName)
		}
	}

	return nil
}

func (fm FeatureMap) SetFromYaml(r io.Reader, logger *logrus.Logger) error {
	var cfg map[string]bool

	// parse config file
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil {
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to parse feature flags: %w", err)
		}

		logger.Debug("No feature flags in config file")
	}

	// set features
	for k, v := range cfg {
		err := fm.SetFeature(k, v)

		switch {
		case errors.Is(err, ErrFeatureUnknown):
			logger.Errorf("Ignored feature '%s': %s", k, err)
			continue
		case errors.Is(err, ErrFeatureDeprecated):
			logger.Warningf("Feature '%s': %s", k, err)
		case errors.Is(err, ErrFeatureRetired):
			logger.Errorf("Ignored feature '%s': %s", k, err)
			continue
		case errors.Is(err, ErrFeatureAlreadySet):
			logger.Warningf("Ignored feature '%s': %s", k, err)
			continue
		case err != nil:
			return err
		}

		if v {
			logger.Infof("Enabled feature '%s' with config file", k)
		} else {
			logger.Infof("Disabled feature '%s' with config file", k)
		}
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

// GetFeatureStatus returns the runtime status of all feature flags
func (fm FeatureMap) GetFeatureStatus() (map[string]bool, error) {
	var err error

	fstatus := make(map[string]bool)

	for k := range fm {
		fstatus[k], err = fm.IsFeatureEnabled(k)
		if err != nil {
			return nil, err
		}
	}

	return fstatus, nil
}
