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


// LoadFeatureFlags parses {ConfigDir}/feature.yaml to enable feature flags.
func LoadFeatureFlagsFile(cConfig *Config, logger *log.Logger) error {
	featurePath := filepath.Join(cConfig.ConfigPaths.ConfigDir, "feature.yaml")

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
