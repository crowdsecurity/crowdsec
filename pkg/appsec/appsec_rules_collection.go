package appsec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

type AppsecCollection struct {
	Rules       []string
	NativeRules []string
}

const APPSEC_RULE = "appsec-rule"

// to be filled w/ seb update
type AppsecCollectionConfig struct {
	Type              string                   `yaml:"type"`
	Name              string                   `yaml:"name"`
	Debug             bool                     `yaml:"debug"`
	Description       string                   `yaml:"description"`
	SecLangFilesRules []string                 `yaml:"seclang_files_rules"`
	SecLangRules      []string                 `yaml:"seclang_rules"`
	Rules             []appsec_rule.CustomRule `yaml:"rules"`
	Severity          string                   `yaml:"severity"`

	Labels map[string]any `yaml:"labels"` // Labels is K:V list aiming at providing context the overflow

	Data    []*enrichment.DataProvider `yaml:"data"`
	hash    string
	version string
}

type RulesDetails struct {
	LogLevel log.Level
	Hash     string
	Version  string
	Name     string
}

// FIXME: this shouldn't be a global
// Is using the id is a good idea ? might be too specific to coraza and not easily reusable
var AppsecRulesDetails = make(map[int]RulesDetails)

// matchPattern reports whether appsecRule.Name matches pattern.
func matchPattern(pattern, name string, logger *log.Entry) bool {
	tmpMatch, err := exprhelpers.Match(pattern, name)
	if err != nil {
		logger.Errorf("unable to match %s with %s : %s", name, pattern, err)
		return false
	}

	matched, ok := tmpMatch.(bool)
	if !ok {
		logger.Errorf("unable to match %s with %s : result is not a boolean", name, pattern)
		return false
	}

	return matched
}

// loadNativeRulesFromFile reads a single seclang rules file and returns its non-comment, non-empty lines.
func loadNativeRulesFromFile(fullPath string, logger *log.Entry) []string {
	c, err := os.ReadFile(fullPath)
	if err != nil {
		logger.Errorf("unable to read file %s : %s", fullPath, err)
		return nil
	}

	rules := make([]string, 0)

	for line := range strings.SplitSeq(string(c), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}

		if strings.TrimSpace(line) == "" {
			continue
		}

		rules = append(rules, line)
	}

	return rules
}

// loadSecLangFilesRules resolves the seclang file globs and appends their rules to appsecCol.
func loadSecLangFilesRules(appsecRule AppsecCollectionConfig, hub *cwhub.Hub, logger *log.Entry, appsecCol *AppsecCollection) {
	for _, rulesFile := range appsecRule.SecLangFilesRules {
		logger.Debugf("Adding rules from %s", rulesFile)
		globPattern := filepath.Join(hub.GetDataDir(), rulesFile)

		matches, err := filepath.Glob(globPattern)
		if err != nil {
			logger.Errorf("unable to glob %s : %s", rulesFile, err)
			continue
		}

		if len(matches) == 0 {
			logger.Warnf("no file matched pattern %s", globPattern)
			continue
		}

		for _, fullPath := range matches {
			appsecCol.NativeRules = append(appsecCol.NativeRules, loadNativeRulesFromFile(fullPath, logger)...)
		}
	}
}

// registerRuleDetails records the metadata and debug flags for a converted custom rule.
func registerRuleDetails(appsecRule AppsecCollectionConfig, ruleName string, rulesId []uint32, logger *log.Entry) {
	// We only take the first id, as it's the one of the "main" rule
	if _, ok := AppsecRulesDetails[int(rulesId[0])]; !ok {
		AppsecRulesDetails[int(rulesId[0])] = RulesDetails{
			LogLevel: log.InfoLevel,
			Hash:     appsecRule.hash,
			Version:  appsecRule.version,
			Name:     appsecRule.Name,
		}
	} else {
		logger.Warnf("conflicting id %d for rule %s !", rulesId[0], ruleName)
	}

	for _, id := range rulesId {
		SetRuleDebug(int(id), appsecRule.Debug)
	}
}

// loadCustomRules converts the YAML custom rules and appends the resulting seclang rules to appsecCol.
func loadCustomRules(appsecRule AppsecCollectionConfig, logger *log.Entry, appsecCol *AppsecCollection) error {
	for _, rule := range appsecRule.Rules {
		rule.Severity = appsecRule.Severity

		strRule, rulesId, err := rule.Convert(appsec_rule.ModsecurityRuleType, appsecRule.Name, appsecRule.Description)
		if err != nil {
			logger.Errorf("unable to convert rule %s : %s", appsecRule.Name, err)
			return err
		}

		logger.Debugf("Adding rule %s", strRule)
		appsecCol.Rules = append(appsecCol.Rules, strRule)

		registerRuleDetails(appsecRule, rule.Name, rulesId, logger)
	}

	return nil
}

// initRuleData initializes the data files referenced by an appsec rule.
func initRuleData(appsecRule AppsecCollectionConfig, hub *cwhub.Hub, logger *log.Entry) {
	for _, appsecRuleData := range appsecRule.Data {
		if appsecRuleData.DestPath == "" {
			logger.Errorf("missing dest_path for rule %s : %+v", appsecRule.Name, appsecRuleData)
			continue
		}

		if err := exprhelpers.FileInit(hub.GetDataDir(), appsecRuleData.DestPath, appsecRuleData.Type); err != nil {
			logger.Errorf("unable to initialize data file %s : %s", appsecRuleData.DestPath, err)
			continue
		}
	}
}

func LoadCollection(pattern string, logger *log.Entry, hub *cwhub.Hub) ([]AppsecCollection, error) {
	ret := make([]AppsecCollection, 0)

	for _, appsecRule := range appsecRules {
		if !matchPattern(pattern, appsecRule.Name, logger) {
			continue
		}

		appsecCol := AppsecCollection{}

		loadSecLangFilesRules(appsecRule, hub, logger, &appsecCol)

		if appsecRule.SecLangRules != nil {
			logger.Tracef("Adding inline rules %+v", appsecRule.SecLangRules)
			appsecCol.NativeRules = append(appsecCol.NativeRules, appsecRule.SecLangRules...)
		}

		if err := loadCustomRules(appsecRule, logger, &appsecCol); err != nil {
			return nil, err
		}

		initRuleData(appsecRule, hub, logger)

		ret = append(ret, appsecCol)
	}

	if len(ret) == 0 {
		return nil, fmt.Errorf("no appsec-rules found for pattern %s", pattern)
	}

	return ret, nil
}

func (w AppsecCollection) String() string {
	ret := ""
	for _, rule := range w.Rules {
		ret += rule + "\n"
	}

	return ret
}
