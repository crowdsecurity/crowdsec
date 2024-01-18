package hubtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installParserItem(hubParser *cwhub.Item) error {
	parserSource, err := filepath.Abs(filepath.Join(t.HubPath, hubParser.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %s", parserSource, err)
	}

	parserFileName := filepath.Base(parserSource)

	// runtime/hub/parsers/s00-raw/crowdsecurity/
	hubDirParserDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubParser.RemotePath))

	// runtime/parsers/s00-raw/
	parserDirDest := fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, hubParser.Stage)

	if err := os.MkdirAll(hubDirParserDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %s", hubDirParserDest, err)
	}

	if err := os.MkdirAll(parserDirDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %s", parserDirDest, err)
	}

	// runtime/hub/parsers/s00-raw/crowdsecurity/syslog-logs.yaml
	hubDirParserPath := filepath.Join(hubDirParserDest, parserFileName)
	if err := Copy(parserSource, hubDirParserPath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %s", parserSource, hubDirParserPath, err)
	}

	// runtime/parsers/s00-raw/syslog-logs.yaml
	parserDirParserPath := filepath.Join(parserDirDest, parserFileName)
	if err := os.Symlink(hubDirParserPath, parserDirParserPath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink parser '%s' to '%s': %s", hubDirParserPath, parserDirParserPath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installParserCustom(parser string) error {
	customParserExist := false
	for _, customPath := range t.CustomItemsLocation {
		// we check if its a custom parser
		customParserPath := filepath.Join(customPath, parser)
		if _, err := os.Stat(customParserPath); os.IsNotExist(err) {
			continue
			//return fmt.Errorf("parser '%s' doesn't exist in the hub and doesn't appear to be a custom one.", parser)
		}

		customParserPathSplit, customParserName := filepath.Split(customParserPath)
		// because path is parsers/<stage>/<author>/parser.yaml and we wan't the stage
		splittedPath := strings.Split(customParserPathSplit, string(os.PathSeparator))
		customParserStage := splittedPath[len(splittedPath)-3]

		// check if stage exist
		hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("parsers/%s", customParserStage))

		if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
			continue
			//return fmt.Errorf("stage '%s' extracted from '%s' doesn't exist in the hub", customParserStage, hubStagePath)
		}

		parserDirDest := fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, customParserStage)
		if err := os.MkdirAll(parserDirDest, os.ModePerm); err != nil {
			continue
			//return fmt.Errorf("unable to create folder '%s': %s", parserDirDest, err)
		}

		customParserDest := filepath.Join(parserDirDest, customParserName)
		// if path to parser exist, copy it
		if err := Copy(customParserPath, customParserDest); err != nil {
			continue
			//return fmt.Errorf("unable to copy custom parser '%s' to '%s': %s", customParserPath, customParserDest, err)
		}

		customParserExist = true
		break
	}
	if !customParserExist {
		return fmt.Errorf("couldn't find custom parser '%s' in the following location: %+v", parser, t.CustomItemsLocation)
	}

	return nil
}

func (t *HubTestItem) installParser(name string) error {
	if item := t.HubIndex.GetItem(cwhub.PARSERS, name); item != nil {
		return t.installParserItem(item)
	}

	return t.installParserCustom(name)
}
