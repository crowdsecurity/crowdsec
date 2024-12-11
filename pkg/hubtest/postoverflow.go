package hubtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installPostoverflowItem(item *cwhub.Item) error {
	sourcePath, err := filepath.Abs(filepath.Join(t.HubPath, item.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %w", sourcePath, err)
	}

	sourceFilename := filepath.Base(sourcePath)

	// runtime/hub/postoverflows/s00-enrich/crowdsecurity/
	hubDirPostoverflowDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(item.RemotePath))

	// runtime/postoverflows/s00-enrich
	itemTypeDirDest := fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, item.Stage)

	if err := createDirs([]string{hubDirPostoverflowDest, itemTypeDirDest}); err != nil {
		return err
	}

	// runtime/hub/postoverflows/s00-enrich/crowdsecurity/rdns.yaml
	hubDirPostoverflowPath := filepath.Join(hubDirPostoverflowDest, sourceFilename)
	if err := Copy(sourcePath, hubDirPostoverflowPath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %w", sourcePath, hubDirPostoverflowPath, err)
	}

	// runtime/postoverflows/s00-enrich/rdns.yaml
	postoverflowDirParserPath := filepath.Join(itemTypeDirDest, sourceFilename)
	if err := os.Symlink(hubDirPostoverflowPath, postoverflowDirParserPath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink postoverflow '%s' to '%s': %w", hubDirPostoverflowPath, postoverflowDirParserPath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installPostoverflowCustomFrom(postoverflow string, customPath string) (bool, error) {
	// we check if its a custom postoverflow
	customPostOverflowPath := filepath.Join(customPath, postoverflow)
	if _, err := os.Stat(customPostOverflowPath); os.IsNotExist(err) {
		return false, nil
	}

	customPostOverflowPathSplit := strings.Split(customPostOverflowPath, "/")
	customPostoverflowName := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-1]
	// because path is postoverflows/<stage>/<author>/parser.yaml and we wan't the stage
	customPostoverflowStage := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-3]

	// check if stage exist
	hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("postoverflows/%s", customPostoverflowStage))
	if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
		return false, fmt.Errorf("stage '%s' from extracted '%s' doesn't exist in the hub", customPostoverflowStage, hubStagePath)
	}

	stageDirDest := fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, customPostoverflowStage)
	if err := os.MkdirAll(stageDirDest, os.ModePerm); err != nil {
		return false, fmt.Errorf("unable to create folder '%s': %w", stageDirDest, err)
	}

	customPostoverflowDest := filepath.Join(stageDirDest, customPostoverflowName)
	// if path to postoverflow exist, copy it
	if err := Copy(customPostOverflowPath, customPostoverflowDest); err != nil {
		return false, fmt.Errorf("unable to copy custom parser '%s' to '%s': %w", customPostOverflowPath, customPostoverflowDest, err)
	}

	return true, nil
}

func (t *HubTestItem) installPostoverflowCustom(postoverflow string) error {
	for _, customPath := range t.CustomItemsLocation {
		found, err := t.installPostoverflowCustomFrom(postoverflow, customPath)
		if err != nil {
			return err
		}

		if found {
			return nil
		}
	}

	return fmt.Errorf("couldn't find custom postoverflow '%s' in the following location: %+v", postoverflow, t.CustomItemsLocation)
}

func (t *HubTestItem) installPostoverflow(name string) error {
	if hubPostOverflow := t.HubIndex.GetItem(cwhub.POSTOVERFLOWS, name); hubPostOverflow != nil {
		return t.installPostoverflowItem(hubPostOverflow)
	}

	return t.installPostoverflowCustom(name)
}
