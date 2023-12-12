package appsec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"

	log "github.com/sirupsen/logrus"
)

type AppsecCollection struct {
	collectionName string
	Rules          []string
}

var APPSEC_RULE = "appsec-rule"

// to be filled w/ seb update
type AppsecCollectionConfig struct {
	Type              string                   `yaml:"type"`
	Name              string                   `yaml:"name"`
	Debug             bool                     `yaml:"debug"`
	Description       string                   `yaml:"description"`
	SecLangFilesRules []string                 `yaml:"seclang_files_rules"`
	SecLangRules      []string                 `yaml:"seclang_rules"`
	Rules             []appsec_rule.CustomRule `yaml:"rules"`

	Labels map[string]interface{} `yaml:"labels"` //Labels is K:V list aiming at providing context the overflow

	Data    interface{} `yaml:"data"` //Ignore it
	hash    string      `yaml:"-"`
	version string      `yaml:"-"`
}

type RulesDetails struct {
	LogLevel log.Level
	Hash     string
	Version  string
	Name     string
}

// Should it be a global ?
// Is using the id is a good idea ? might be too specific to coraza and not easily reusable
var AppsecRulesDetails = make(map[int]RulesDetails)

func LoadCollection(pattern string, logger *log.Entry) ([]AppsecCollection, error) {
	ret := make([]AppsecCollection, 0)

	for _, appsecRule := range appsecRules {

		tmpMatch, err := exprhelpers.Match(pattern, appsecRule.Name)

		if err != nil {
			logger.Errorf("unable to match %s with %s : %s", appsecRule.Name, pattern, err)
			continue
		}

		matched, ok := tmpMatch.(bool)

		if !ok {
			logger.Errorf("unable to match %s with %s : %s", appsecRule.Name, pattern, err)
			continue
		}

		if !matched {
			continue
		}

		appsecCol := AppsecCollection{
			collectionName: appsecRule.Name,
		}

		if appsecRule.SecLangFilesRules != nil {
			for _, rulesFile := range appsecRule.SecLangFilesRules {
				logger.Debugf("Adding rules from %s", rulesFile)
				fullPath := filepath.Join(hub.GetDataDir(), rulesFile)
				c, err := os.ReadFile(fullPath)
				if err != nil {
					logger.Errorf("unable to read file %s : %s", rulesFile, err)
					continue
				}
				for _, line := range strings.Split(string(c), "\n") {
					if strings.HasPrefix(line, "#") {
						continue
					}
					if strings.TrimSpace(line) == "" {
						continue
					}
					appsecCol.Rules = append(appsecCol.Rules, line)
				}
			}
		}

		if appsecRule.SecLangRules != nil {
			logger.Tracef("Adding inline rules %+v", appsecRule.SecLangRules)
			appsecCol.Rules = append(appsecCol.Rules, appsecRule.SecLangRules...)
		}

		if appsecRule.Rules != nil {
			for _, rule := range appsecRule.Rules {
				strRule, rulesId, err := rule.Convert(appsec_rule.ModsecurityRuleType, appsecRule.Name)
				if err != nil {
					logger.Errorf("unable to convert rule %s : %s", appsecRule.Name, err)
					return nil, err
				}
				logger.Debugf("Adding rule %s", strRule)
				appsecCol.Rules = append(appsecCol.Rules, strRule)

				//We only take the first id, as it's the one of the "main" rule
				if _, ok := AppsecRulesDetails[int(rulesId[0])]; !ok {
					AppsecRulesDetails[int(rulesId[0])] = RulesDetails{
						LogLevel: log.InfoLevel,
						Hash:     appsecRule.hash,
						Version:  appsecRule.version,
						Name:     appsecRule.Name,
					}
				} else {
					logger.Warnf("conflicting id %d for rule %s !", rulesId[0], rule.Name)
				}

				for _, id := range rulesId {
					SetRuleDebug(int(id), appsecRule.Debug)
				}
			}
		}
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
