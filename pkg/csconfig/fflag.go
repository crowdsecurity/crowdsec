package csconfig

import (
	"fmt"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

// LoadFeatureFlagsEnv parses the environment variables to enable feature flags.
func LoadFeatureFlagsEnv(logger *log.Logger) error {
	if err := fflag.Crowdsec.SetFromEnv(logger); err != nil {
		return err
	}
	return nil
}

// FeatureFlagsFileLocation returns the path to the feature.yaml file.
// The file is in the same directory as config.yaml, which is provided
// as the fist parameter. This can be different than ConfigPaths.ConfigDir
// because we have not read config.yaml yet so we don't know the value of ConfigDir.
func GetFeatureFilePath(configPath string) string {
	dir := filepath.Dir(configPath)
	return filepath.Join(dir, "feature.yaml")
}

// LoadFeatureFlags parses feature.yaml to enable feature flags.
func LoadFeatureFlagsFile(configPath string, logger *log.Logger) error {
	featurePath := GetFeatureFilePath(configPath)

	if err := fflag.Crowdsec.SetFromYamlFile(featurePath, logger); err != nil {
		return fmt.Errorf("file %s: %s", featurePath, err)
	}
	return nil
}

// ListFeatureFlags returns a list of the enabled feature flags.
func ListFeatureFlags() string {
	enabledFeatures := fflag.Crowdsec.GetEnabledFeatures()

	msg := "<none>"
	if len(enabledFeatures) > 0 {
		msg = strings.Join(enabledFeatures, ", ")
	}

	return msg
}
