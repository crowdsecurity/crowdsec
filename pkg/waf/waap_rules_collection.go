package waf

import (
	"os"
	"path/filepath"
	"strings"

	corazatypes "github.com/crowdsecurity/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/waf/waap_rule"

	log "github.com/sirupsen/logrus"
)

// to be filled w/ seb update
type WaapCollection struct {
	collectionName string
	Rules          []string
}

var WAAP_RULE = "waap-rule"

// to be filled w/ seb update
type WaapCollectionConfig struct {
	Type              string                 `yaml:"type"`
	Name              string                 `yaml:"name"`
	Debug             bool                   `yaml:"debug"`
	Description       string                 `yaml:"description"`
	SecLangFilesRules []string               `yaml:"seclang_files_rules"`
	SecLangRules      []string               `yaml:"seclang_rules"`
	Rules             []waap_rule.CustomRule `yaml:"rules"`

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
var WaapRulesDetails = make(map[int]RulesDetails)

func LoadCollection(pattern string) ([]WaapCollection, error) {
	//FIXME: have a proper logger here, inheriting from waap-config to have consistent log levels
	ret := make([]WaapCollection, 0)

	for _, waapRule := range waapRules {

		tmpMatch, err := exprhelpers.Match(pattern, waapRule.Name)

		if err != nil {
			log.Errorf("unable to match %s with %s : %s", waapRule.Name, pattern, err)
			continue
		}

		matched, ok := tmpMatch.(bool)

		if !ok {
			log.Errorf("unable to match %s with %s : %s", waapRule.Name, pattern, err)
			continue
		}

		if !matched {
			continue
		}

		waapCol := WaapCollection{
			collectionName: waapRule.Name,
		}

		if waapRule.SecLangFilesRules != nil {
			for _, rulesFile := range waapRule.SecLangFilesRules {
				fullPath := filepath.Join(hub.GetDataDir(), rulesFile)
				c, err := os.ReadFile(fullPath)
				if err != nil {
					log.Errorf("unable to read file %s : %s", rulesFile, err)
					continue
				}
				for _, line := range strings.Split(string(c), "\n") {
					if strings.HasPrefix(line, "#") {
						continue
					}
					if strings.TrimSpace(line) == "" {
						continue
					}
					waapCol.Rules = append(waapCol.Rules, line)
				}
			}
		}

		if waapRule.SecLangRules != nil {
			waapCol.Rules = append(waapCol.Rules, waapRule.SecLangRules...)
		}

		if waapRule.Rules != nil {
			for _, rule := range waapRule.Rules {
				strRule, rulesId, err := rule.Convert(waap_rule.ModsecurityRuleType, waapRule.Name)
				if err != nil {
					log.Errorf("unable to convert rule %s : %s", rule.Name, err)
					return nil, err
				}
				log.Debugf("Adding rule %s", strRule)
				waapCol.Rules = append(waapCol.Rules, strRule)

				//We only take the first id, as it's the one of the "main" rule
				if _, ok := WaapRulesDetails[int(rulesId[0])]; !ok {
					WaapRulesDetails[int(rulesId[0])] = RulesDetails{
						LogLevel: log.InfoLevel,
						Hash:     waapRule.hash,
						Version:  waapRule.version,
						Name:     waapRule.Name,
					}
				} else {
					log.Warnf("conflicting id %d for rule %s !", rulesId[0], rule.Name)
				}

				for _, id := range rulesId {
					SetRuleDebug(int(id), waapRule.Debug)
				}
			}
		}
		ret = append(ret, waapCol)
	}
	return ret, nil
}

func (wcc WaapCollectionConfig) LoadCollection(collection string) (WaapCollection, error) {
	return WaapCollection{}, nil
}

func (w WaapCollection) Check() error {
	return nil
}

func (w WaapCollection) Eval(req ParsedRequest) (*corazatypes.Interruption, error) {
	return nil, nil
}

func (w WaapCollection) GetDisplayName() string {
	return w.collectionName
}

func (w WaapCollection) String() string {
	ret := ""
	for _, rule := range w.Rules {
		ret += rule + "\n"
	}
	return ret
}
