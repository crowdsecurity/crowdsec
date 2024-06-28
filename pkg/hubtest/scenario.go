package hubtest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installScenarioItem(item *cwhub.Item) error {
	sourcePath, err := filepath.Abs(filepath.Join(t.HubPath, item.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %w", sourcePath, err)
	}

	sourceFilename := filepath.Base(sourcePath)

	// runtime/hub/scenarios/crowdsecurity/
	hubDirScenarioDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(item.RemotePath))

	// runtime/parsers/scenarios/
	itemTypeDirDest := fmt.Sprintf("%s/scenarios/", t.RuntimePath)

	if err := createDirs([]string{hubDirScenarioDest, itemTypeDirDest}); err != nil {
		return err
	}

	// runtime/hub/scenarios/crowdsecurity/ssh-bf.yaml
	hubDirScenarioPath := filepath.Join(hubDirScenarioDest, sourceFilename)
	if err := Copy(sourcePath, hubDirScenarioPath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %w", sourcePath, hubDirScenarioPath, err)
	}

	// runtime/scenarios/ssh-bf.yaml
	scenarioDirParserPath := filepath.Join(itemTypeDirDest, sourceFilename)
	if err := os.Symlink(hubDirScenarioPath, scenarioDirParserPath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink scenario '%s' to '%s': %w", hubDirScenarioPath, scenarioDirParserPath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installScenarioCustomFrom(scenario string, customPath string) (bool, error) {
	// we check if its a custom scenario
	customScenarioPath := filepath.Join(customPath, scenario)
	if _, err := os.Stat(customScenarioPath); os.IsNotExist(err) {
		return false, nil
	}

	itemTypeDirDest := fmt.Sprintf("%s/scenarios/", t.RuntimePath)
	if err := os.MkdirAll(itemTypeDirDest, os.ModePerm); err != nil {
		return false, fmt.Errorf("unable to create folder '%s': %w", itemTypeDirDest, err)
	}

	scenarioFileName := filepath.Base(customScenarioPath)

	scenarioFileDest := filepath.Join(itemTypeDirDest, scenarioFileName)
	if err := Copy(customScenarioPath, scenarioFileDest); err != nil {
		return false, fmt.Errorf("unable to copy scenario from '%s' to '%s': %w", customScenarioPath, scenarioFileDest, err)
	}

	return true, nil
}

func (t *HubTestItem) installScenarioCustom(scenario string) error {
	for _, customPath := range t.CustomItemsLocation {
		found, err := t.installScenarioCustomFrom(scenario, customPath)
		if err != nil {
			return err
		}

		if found {
			return nil
		}
	}

	return fmt.Errorf("couldn't find custom scenario '%s' in the following location: %+v", scenario, t.CustomItemsLocation)
}

func (t *HubTestItem) installScenario(name string) error {
	if item := t.HubIndex.GetItem(cwhub.SCENARIOS, name); item != nil {
		return t.installScenarioItem(item)
	}

	return t.installScenarioCustom(name)
}
