package appsec

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

var appsecRules = make(map[string]AppsecCollectionConfig) // FIXME: would probably be better to have a struct for this

func LoadAppsecRules(hub *cwhub.Hub) error {
	appsecRules = make(map[string]AppsecCollectionConfig)

	for _, hubAppsecRuleItem := range hub.GetInstalledByType(cwhub.APPSEC_RULES, false) {
		content, err := os.ReadFile(hubAppsecRuleItem.State.LocalPath)
		if err != nil {
			log.Warnf("unable to read file %s : %s", hubAppsecRuleItem.State.LocalPath, err)
			continue
		}

		var rule AppsecCollectionConfig

		err = yaml.UnmarshalStrict(content, &rule)
		if err != nil {
			log.Warnf("unable to parse file %s : %s", hubAppsecRuleItem.State.LocalPath, err)
			continue
		}

		if rule.Name == "" {
			return fmt.Errorf("appsec rule name is empty for %s", hubAppsecRuleItem.State.LocalPath)
		}

		rule.hash = hubAppsecRuleItem.State.LocalHash
		rule.version = hubAppsecRuleItem.Version

		log.Infof("Adding %s to appsec rules", rule.Name)

		appsecRules[rule.Name] = rule
	}

	if len(appsecRules) == 0 {
		log.Debugf("No appsec rules found")
	}
	return nil
}
