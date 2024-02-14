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
// still accepted but a warning is logged (only if a deprecation message is provided).
// A retired feature flag is ignored and an error is logged.
//
// The message is inteded to inform the user of the behavior
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

var (
	ErrFeatureNameEmpty   = errors.New("name is empty")
	ErrFeatureNameCase    = errors.New("name is not lowercase")
	ErrFeatureNameInvalid = errors.New("invalid name (allowed a-z, 0-9, _, .)")
	ErrFeatureUnknown     = errors.New("unknown feature")
	ErrFeatureDeprecated  = errors.New("the flag is deprecated")
	ErrFeatureRetired     = errors.New("the flag is retired")
)

const (
	ActiveState     = iota // the feature can be enabled, and its description is logged (Info)
	DeprecatedState        // the feature can be enabled, and a deprecation message is logged (Warning)
	RetiredState           // the feature is ignored and a deprecation message is logged (Error)
)

type Feature struct {
	Name  string
	State int // active, deprecated, retired

	// Description should be a short sentence, explaining the feature.
	Description string

	// DeprecationMessage is used to inform the user of the behavior that has
	// been decided when the flag is/was finally retired.
	DeprecationMsg string

	enabled bool
}

func (f *Feature) IsEnabled() bool {
	return f.enabled
}

// Set enables or disables a feature flag
// It should not be called directly by the user, but by SetFromEnv or SetFromYaml
func (f *Feature) Set(value bool) error {
	// retired feature flags are ignored
	if f.State == RetiredState {
		return ErrFeatureRetired
	}

	f.enabled = value

	// deprecated feature flags are still accepted, but a warning is triggered.
	// We return an error but set the feature anyway.
	if f.State == DeprecatedState {
		return ErrFeatureDeprecated
	}

	return nil
}

// A register allows to enable features from the environment or a file
type FeatureRegister struct {
	EnvPrefix string
	features  map[string]*Feature
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

func (fr *FeatureRegister) RegisterFeature(feat *Feature) error {
	if err := validateFeatureName(feat.Name); err != nil {
		return fmt.Errorf("feature flag '%s': %w", feat.Name, err)
	}

	if fr.features == nil {
		fr.features = make(map[string]*Feature)
	}

	fr.features[feat.Name] = feat

	return nil
}

func (fr *FeatureRegister) GetFeature(featureName string) (*Feature, error) {
	feat, ok := fr.features[featureName]
	if !ok {
		return feat, ErrFeatureUnknown
	}

	return feat, nil
}

func (fr *FeatureRegister) SetFromEnv(logger *logrus.Logger) error {
	for _, e := range os.Environ() {
		// ignore non-feature variables
		if !strings.HasPrefix(e, fr.EnvPrefix) {
			continue
		}

		// extract feature name and value
		pair := strings.SplitN(e, "=", 2)
		varName := pair[0]
		featureName := strings.ToLower(varName[len(fr.EnvPrefix):])
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

		feat, err := fr.GetFeature(featureName)
		if err != nil {
			logger.Errorf("Ignored envvar '%s': %s.", varName, err)
			continue
		}

		err = feat.Set(enable)

		switch {
		case errors.Is(err, ErrFeatureRetired):
			logger.Errorf("Ignored envvar '%s': %s. %s", varName, err, feat.DeprecationMsg)
			continue
		case errors.Is(err, ErrFeatureDeprecated):
			if feat.DeprecationMsg != "" {
				logger.Warningf("Envvar '%s': %s. %s", varName, err, feat.DeprecationMsg)
			}
		case err != nil:
			return err
		}

		logger.Debugf("Feature flag: %s=%t (from envvar). %s", featureName, enable, feat.Description)
	}

	return nil
}

func (fr *FeatureRegister) SetFromYaml(r io.Reader, logger *logrus.Logger) error {
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
		feat, err := fr.GetFeature(k)
		if err != nil {
			logger.Errorf("Ignored feature flag '%s': %s", k, err)
			continue
		}

		err = feat.Set(true)

		switch {
		case errors.Is(err, ErrFeatureRetired):
			logger.Errorf("Ignored feature flag '%s': %s. %s", k, err, feat.DeprecationMsg)
			continue
		case errors.Is(err, ErrFeatureDeprecated):
			logger.Warningf("Feature '%s': %s. %s", k, err, feat.DeprecationMsg)
		case err != nil:
			return err
		}

		logger.Debugf("Feature flag: %s=true (from config file). %s", k, feat.Description)
	}

	return nil
}

func (fr *FeatureRegister) SetFromYamlFile(path string, logger *logrus.Logger) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Tracef("Feature flags config file '%s' does not exist", path)

			return nil
		}

		return fmt.Errorf("failed to open feature flags file: %w", err)
	}
	defer f.Close()

	logger.Debugf("Reading feature flags from %s", path)

	return fr.SetFromYaml(f, logger)
}

// GetEnabledFeatures returns the list of features that have been enabled by the user
func (fr *FeatureRegister) GetEnabledFeatures() []string {
	ret := make([]string, 0)

	for k, feat := range fr.features {
		if feat.IsEnabled() {
			ret = append(ret, k)
		}
	}

	sort.Strings(ret)

	return ret
}

// GetAllFeatures returns a slice of all the known features, ordered by name
func (fr *FeatureRegister) GetAllFeatures() []Feature {
	ret := make([]Feature, len(fr.features))

	i := 0
	for _, feat := range fr.features {
		ret[i] = *feat
		i++
	}

	sort.Slice(ret, func(i, j int) bool {
		return ret[i].Name < ret[j].Name
	})

	return ret
}
