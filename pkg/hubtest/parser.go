package hubtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installParserItem(item *cwhub.Item) error {
	sourcePath, err := filepath.Abs(filepath.Join(t.HubPath, item.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %w", sourcePath, err)
	}

	sourceFilename := filepath.Base(sourcePath)

	// runtime/hub/parsers/s00-raw/crowdsecurity/
	hubDirParserDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(item.RemotePath))

	// runtime/parsers/s00-raw/
	itemTypeDirDest := fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, item.Stage)

	if err := createDirs([]string{hubDirParserDest, itemTypeDirDest}); err != nil {
		return err
	}

	// runtime/hub/parsers/s00-raw/crowdsecurity/syslog-logs.yaml
	hubDirParserPath := filepath.Join(hubDirParserDest, sourceFilename)
	if err := Copy(sourcePath, hubDirParserPath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %w", sourcePath, hubDirParserPath, err)
	}

	// runtime/parsers/s00-raw/syslog-logs.yaml
	parserDirParserPath := filepath.Join(itemTypeDirDest, sourceFilename)
	if err := os.Symlink(hubDirParserPath, parserDirParserPath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink parser '%s' to '%s': %w", hubDirParserPath, parserDirParserPath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installParserCustomFrom(parser string, customPath string) (bool, error) {
	// we check if its a custom parser
	customParserPath := filepath.Join(customPath, parser)
	if _, err := os.Stat(customParserPath); os.IsNotExist(err) {
		return false, nil
	}

	customParserPathSplit, customParserName := filepath.Split(customParserPath)
	// because path is parsers/<stage>/<author>/parser.yaml and we wan't the stage
	splitPath := strings.Split(customParserPathSplit, string(os.PathSeparator))
	customParserStage := splitPath[len(splitPath)-3]

	// check if stage exist
	hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("parsers/%s", customParserStage))
	if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
		return false, fmt.Errorf("stage '%s' extracted from '%s' doesn't exist in the hub", customParserStage, hubStagePath)
	}

	stageDirDest := fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, customParserStage)
	if err := os.MkdirAll(stageDirDest, os.ModePerm); err != nil {
		return false, fmt.Errorf("unable to create folder '%s': %w", stageDirDest, err)
	}

	customParserDest := filepath.Join(stageDirDest, customParserName)
	// if path to parser exist, copy it
	if err := Copy(customParserPath, customParserDest); err != nil {
		return false, fmt.Errorf("unable to copy custom parser '%s' to '%s': %w", customParserPath, customParserDest, err)
	}

	return true, nil
}

func (t *HubTestItem) installParserCustom(parser string) error {
	for _, customPath := range t.CustomItemsLocation {
		found, err := t.installParserCustomFrom(parser, customPath)
		if err != nil {
			return err
		}

		if found {
			return nil
		}
	}

	return fmt.Errorf("couldn't find custom parser '%s' in the following locations: %+v", parser, t.CustomItemsLocation)
}

func (t *HubTestItem) installParser(name string) error {
	if item := t.HubIndex.GetItem(cwhub.PARSERS, name); item != nil {
		return t.installParserItem(item)
	}

	return t.installParserCustom(name)
}
