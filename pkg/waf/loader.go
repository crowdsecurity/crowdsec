package waf

import (
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var waapRules map[string]WaapCollectionConfig = make(map[string]WaapCollectionConfig) //FIXME: would probably be better to have a struct for this

func LoadWaapRules() error {
	hub, err := cwhub.GetHub()
	if err != nil {
		return fmt.Errorf("unable to load hub : %s", err)
	}

	for _, hubWafRuleItem := range hub.GetItemMap(cwhub.WAAP_RULES) {
		//log.Infof("loading %s", hubWafRuleItem.LocalPath)
		if !hubWafRuleItem.Installed {
			continue
		}

		content, err := os.ReadFile(hubWafRuleItem.LocalPath)

		if err != nil {
			log.Warnf("unable to read file %s : %s", hubWafRuleItem.LocalPath, err)
			continue
		}

		var rule WaapCollectionConfig

		err = yaml.UnmarshalStrict(content, &rule)

		if err != nil {
			log.Warnf("unable to unmarshal file %s : %s", hubWafRuleItem.LocalPath, err)
			continue
		}

		if rule.Type != WAAP_RULE {
			log.Warnf("unexpected type %s instead of %s for file %s", rule.Type, WAAP_RULE, hubWafRuleItem.LocalPath)
			continue
		}

		rule.hash = hubWafRuleItem.LocalHash
		rule.version = hubWafRuleItem.Version

		log.Infof("Adding %s to waap rules", rule.Name)

		waapRules[rule.Name] = rule
	}

	if len(waapRules) == 0 {
		return fmt.Errorf("no waap rules found in hub")
	}
	return nil
}
