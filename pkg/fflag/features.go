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

const (
	ActiveState = iota
	DeprecatedState
	RetiredState
)

type FeatureFlag struct {
	State          int    // active, deprecated, retired
	DeprecationMsg string // Why was it deprecated? What happens next? What should the user do?
}

type feature struct {
	name	string
	flag    FeatureFlag
	enabled bool
	fm      *FeatureMap
}

func (f *feature) IsEnabled() bool {
	return f.enabled
}

func (f *feature) Set(value bool) error {
	// retired feature flags are ignored
	if f.flag.State == RetiredState {
		return FeatureRetiredError(*f)
	}

	f.enabled = value
	(*f.fm)[f.name] = *f

	// deprecated feature flags are still accepted, but a warning is triggered.
	// We return an error but set the feature anyway.
	if f.flag.State == DeprecatedState {
		return FeatureDeprecatedError(*f)
	}

	return nil
}

type FeatureMap map[string]feature

// These are returned by the constructor.
var (
	ErrFeatureNameEmpty   = errors.New("name is empty")
	ErrFeatureNameCase    = errors.New("name is not lowercase")
	ErrFeatureNameInvalid = errors.New("invalid name (allowed a-z, 0-9, _, .)")
)

var ErrFeatureUnknown = errors.New("unknown feature")
var ErrFeatureDeprecated  = errors.New("the flag is deprecated")

func FeatureDeprecatedError(feat feature) error {
	if feat.flag.DeprecationMsg != "" {
		return fmt.Errorf("%w: %s", ErrFeatureDeprecated, feat.flag.DeprecationMsg)
	}

	return ErrFeatureDeprecated
}

var ErrFeatureRetired = errors.New("the flag is retired")

func FeatureRetiredError(feat feature) error {
	if feat.flag.DeprecationMsg != "" {
		return fmt.Errorf("%w: %s", ErrFeatureRetired, feat.flag.DeprecationMsg)
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

func NewFeatureMap(flags map[string]FeatureFlag) (FeatureMap, error) {
	fm := FeatureMap{}

	for k, v := range flags {
		if err := validateFeatureName(k); err != nil {
			return nil, fmt.Errorf("feature flag '%s': %w", k, err)
		}

		fm[k] = feature{name: k, flag: v, enabled: false, fm: &fm}
	}

	return fm, nil
}

func (fm *FeatureMap) GetFeature(featureName string) (feature, error) {
	feat, ok := (*fm)[featureName]
	if !ok {
		return feat, ErrFeatureUnknown
	}

	return feat, nil
}

func (fm *FeatureMap) SetFromEnv(prefix string, logger *logrus.Logger) error {
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

		feat, err := fm.GetFeature(featureName)
		if err != nil {
			logger.Errorf("Ignored envvar '%s': %s", varName, err)
			continue
		}

		err = feat.Set(enable)

		switch {
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

func (fm *FeatureMap) SetFromYaml(r io.Reader, logger *logrus.Logger) error {
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
		feat, err := fm.GetFeature(k)
		if err != nil {
			logger.Errorf("Ignored feature flag '%s': %s", k, err)
			continue
		}

		err = feat.Set(true)

		switch {
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

func (fm *FeatureMap) SetFromYamlFile(path string, logger *logrus.Logger) error {
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
func (fm *FeatureMap) GetEnabledFeatures() []string {
	ret := make([]string, 0)

	for k := range *fm {
		feat := (*fm)[k]
		if feat.IsEnabled() {
			ret = append(ret, k)
		}
	}

	sort.Strings(ret)

	return ret
}
