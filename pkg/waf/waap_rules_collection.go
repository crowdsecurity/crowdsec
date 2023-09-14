package waf

import (
	"fmt"
	"os"

	corazatypes "github.com/crowdsecurity/coraza/v3/types"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

// to be filled w/ seb update
type WaapCollection struct {
	collectionName string
}

// to be filled w/ seb update
type WaapCollectionConfig struct {
	Type              string   `yaml:"type"`
	Name              string   `yaml:"name"`
	SecLangFilesRules []string `yaml:"seclang_files_rules"`
	SecLangRules      []string `yaml:"seclang_rules"`
	MergedRules       []string `yaml:"-"`
}

func LoadCollection(collection string) (WaapCollection, error) {

	//FIXME: do it once globally
	var waapRules map[string]WaapCollectionConfig
	for _, hubWafRuleItem := range cwhub.GetItemMap(cwhub.WAF_RULES) {
		if !hubWafRuleItem.Installed {
			continue
		}

		content, err := os.ReadFile(hubWafRuleItem.LocalPath)

		if err != nil {
			log.Warnf("unable to read file %s : %s", hubWafRuleItem.LocalPath, err)
			continue
		}

		var rule WaapCollectionConfig

		err = yaml.Unmarshal(content, &rule)

		if err != nil {
			log.Warnf("unable to unmarshal file %s : %s", hubWafRuleItem.LocalPath, err)
			continue
		}

		if rule.Type != "waap-rule" {
			log.Warnf("unexpected type %s instead of waap-rule for file %s", rule.Type, hubWafRuleItem.LocalPath)
			continue
		}
		waapRules[rule.Name] = rule
	}

	if len(waapRules) == 0 {
		return WaapCollection{}, fmt.Errorf("no waap rules found in hub")
	}

	var loadedRule WaapCollectionConfig

	if loadedRule, ok := waapRules[collection]; !ok {
		return WaapCollection{}, fmt.Errorf("no waap rules found for collection %s", collection)
	}

	return WaapCollection{
		collectionName: loadedRule.Name,
	}, nil
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
