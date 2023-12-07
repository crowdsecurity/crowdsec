package appsec

import (
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var appsecRules map[string]AppsecCollectionConfig = make(map[string]AppsecCollectionConfig) //FIXME: would probably be better to have a struct for this

var hub *cwhub.Hub //FIXME: this is a temporary hack to make the hub available in the package

func LoadAppsecRules(hubInstance *cwhub.Hub) error {

	hub = hubInstance

	for _, hubAppsecRuleItem := range hub.GetItemMap(cwhub.APPSEC_RULES) {
		if !hubAppsecRuleItem.State.Installed {
			continue
		}

		content, err := os.ReadFile(hubAppsecRuleItem.State.LocalPath)

		if err != nil {
			log.Warnf("unable to read file %s : %s", hubAppsecRuleItem.State.LocalPath, err)
			continue
		}

		var rule AppsecCollectionConfig

		err = yaml.UnmarshalStrict(content, &rule)

		if err != nil {
			log.Warnf("unable to unmarshal file %s : %s", hubAppsecRuleItem.State.LocalPath, err)
			continue
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
