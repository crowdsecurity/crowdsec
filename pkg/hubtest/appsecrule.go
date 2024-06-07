package hubtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installAppsecRuleItem(item *cwhub.Item) error {
	sourcePath, err := filepath.Abs(filepath.Join(t.HubPath, item.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %w", sourcePath, err)
	}

	sourceFilename := filepath.Base(sourcePath)

	// runtime/hub/appsec-rules/author/appsec-rule
	hubDirAppsecRuleDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(item.RemotePath))

	// runtime/appsec-rules/
	itemTypeDirDest := fmt.Sprintf("%s/appsec-rules/", t.RuntimePath)

	if err := createDirs([]string{hubDirAppsecRuleDest, itemTypeDirDest}); err != nil {
		return err
	}

	// runtime/hub/appsec-rules/crowdsecurity/rule.yaml
	hubDirAppsecRulePath := filepath.Join(itemTypeDirDest, sourceFilename)
	if err := Copy(sourcePath, hubDirAppsecRulePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %w", sourcePath, hubDirAppsecRulePath, err)
	}

	// runtime/appsec-rules/rule.yaml
	appsecRulePath := filepath.Join(itemTypeDirDest, sourceFilename)
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

	itemTypeDirDest := fmt.Sprintf("%s/appsec-rules/", t.RuntimePath)
	if err := os.MkdirAll(itemTypeDirDest, os.ModePerm); err != nil {
		return false, fmt.Errorf("unable to create folder '%s': %w", itemTypeDirDest, err)
	}

	customAppsecRuleDest := fmt.Sprintf("%s/appsec-rules/%s", t.RuntimePath, customAppsecRuleName)
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
