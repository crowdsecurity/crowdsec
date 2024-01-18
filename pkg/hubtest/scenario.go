package hubtest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installScenarioItem(hubScenario *cwhub.Item) error {
	scenarioSource, err := filepath.Abs(filepath.Join(t.HubPath, hubScenario.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path to: %s", scenarioSource)
	}

	scenarioFileName := filepath.Base(scenarioSource)

	// runtime/hub/scenarios/crowdsecurity/
	hubDirScenarioDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubScenario.RemotePath))

	// runtime/parsers/scenarios/
	scenarioDirDest := fmt.Sprintf("%s/scenarios/", t.RuntimePath)

	if err := os.MkdirAll(hubDirScenarioDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %s", hubDirScenarioDest, err)
	}

	if err := os.MkdirAll(scenarioDirDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %s", scenarioDirDest, err)
	}

	// runtime/hub/scenarios/crowdsecurity/ssh-bf.yaml
	hubDirScenarioPath := filepath.Join(hubDirScenarioDest, scenarioFileName)
	if err := Copy(scenarioSource, hubDirScenarioPath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %s", scenarioSource, hubDirScenarioPath, err)
	}

	// runtime/scenarios/ssh-bf.yaml
	scenarioDirParserPath := filepath.Join(scenarioDirDest, scenarioFileName)
	if err := os.Symlink(hubDirScenarioPath, scenarioDirParserPath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink scenario '%s' to '%s': %s", hubDirScenarioPath, scenarioDirParserPath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installScenarioCustom(scenario string) error {
	customScenarioExist := false
	for _, customPath := range t.CustomItemsLocation {
		// we check if its a custom scenario
		customScenarioPath := filepath.Join(customPath, scenario)
		if _, err := os.Stat(customScenarioPath); os.IsNotExist(err) {
			continue
			//return fmt.Errorf("scenarios '%s' doesn't exist in the hub and doesn't appear to be a custom one.", scenario)
		}

		scenarioDirDest := fmt.Sprintf("%s/scenarios/", t.RuntimePath)
		if err := os.MkdirAll(scenarioDirDest, os.ModePerm); err != nil {
			return fmt.Errorf("unable to create folder '%s': %s", scenarioDirDest, err)
		}

		scenarioFileName := filepath.Base(customScenarioPath)
		scenarioFileDest := filepath.Join(scenarioDirDest, scenarioFileName)
		if err := Copy(customScenarioPath, scenarioFileDest); err != nil {
			continue
			//return fmt.Errorf("unable to copy scenario from '%s' to '%s': %s", customScenarioPath, scenarioFileDest, err)
		}
		customScenarioExist = true
		break
	}
	if !customScenarioExist {
		return fmt.Errorf("couldn't find custom scenario '%s' in the following location: %+v", scenario, t.CustomItemsLocation)
	}

	return nil
}

func (t *HubTestItem) installScenario(name string) error {
	if item := t.HubIndex.GetItem(cwhub.SCENARIOS, name); item != nil {
		return t.installScenarioItem(item)
	}

	return t.installScenarioCustom(name)
}
