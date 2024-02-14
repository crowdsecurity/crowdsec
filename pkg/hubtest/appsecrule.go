package hubtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installAppsecRuleItem(hubAppsecRule *cwhub.Item) error {
	appsecRuleSource, err := filepath.Abs(filepath.Join(t.HubPath, hubAppsecRule.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %w", appsecRuleSource, err)
	}

	appsecRuleFilename := filepath.Base(appsecRuleSource)

	// runtime/hub/appsec-rules/author/appsec-rule
	hubDirAppsecRuleDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubAppsecRule.RemotePath))

	// runtime/appsec-rules/
	appsecRuleDirDest := fmt.Sprintf("%s/appsec-rules/", t.RuntimePath)

	if err := os.MkdirAll(hubDirAppsecRuleDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %w", hubDirAppsecRuleDest, err)
	}

	if err := os.MkdirAll(appsecRuleDirDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %w", appsecRuleDirDest, err)
	}

	// runtime/hub/appsec-rules/crowdsecurity/rule.yaml
	hubDirAppsecRulePath := filepath.Join(appsecRuleDirDest, appsecRuleFilename)
	if err := Copy(appsecRuleSource, hubDirAppsecRulePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %w", appsecRuleSource, hubDirAppsecRulePath, err)
	}

	// runtime/appsec-rules/rule.yaml
	appsecRulePath := filepath.Join(appsecRuleDirDest, appsecRuleFilename)
	if err := os.Symlink(hubDirAppsecRulePath, appsecRulePath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink appsec-rule '%s' to '%s': %w", hubDirAppsecRulePath, appsecRulePath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installAppsecRuleCustomFrom(appsecrule string, customPath string) (bool, error) {
	// we check if its a custom appsec-rule
	customAppsecRulePath := filepath.Join(customPath, appsecrule)
	if _, err := os.Stat(customAppsecRulePath); os.IsNotExist(err) {
		return false, nil
	}

	customAppsecRulePathSplit := strings.Split(customAppsecRulePath, "/")
	customAppsecRuleName := customAppsecRulePathSplit[len(customAppsecRulePathSplit)-1]

	appsecRuleDirDest := fmt.Sprintf("%s/appsec-rules/", t.RuntimePath)
	if err := os.MkdirAll(appsecRuleDirDest, os.ModePerm); err != nil {
		return false, fmt.Errorf("unable to create folder '%s': %w", appsecRuleDirDest, err)
	}

	customAppsecRuleDest := fmt.Sprintf("%s/appsec-rules/%s", t.RuntimePath, customAppsecRuleName)
	// if path to postoverflow exist, copy it
	if err := Copy(customAppsecRulePath, customAppsecRuleDest); err != nil {
		return false, fmt.Errorf("unable to copy appsec-rule from '%s' to '%s': %w", customAppsecRulePath, customAppsecRuleDest, err)
	}

	return true, nil
}

func (t *HubTestItem) installAppsecRuleCustom(appsecrule string) error {
	for _, customPath := range t.CustomItemsLocation {
		found, err := t.installAppsecRuleCustomFrom(appsecrule, customPath)
		if err != nil {
			return err
		}

		if found {
			return nil
		}
	}

	return fmt.Errorf("couldn't find custom appsec-rule '%s' in the following location: %+v", appsecrule, t.CustomItemsLocation)
}

func (t *HubTestItem) installAppsecRule(name string) error {
	log.Debugf("adding rule '%s'", name)

	if item := t.HubIndex.GetItem(cwhub.APPSEC_RULES, name); item != nil {
		return t.installAppsecRuleItem(item)
	}

	return t.installAppsecRuleCustom(name)
}
