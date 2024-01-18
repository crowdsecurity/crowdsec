package hubtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installPostoverflowItem(hubPostOverflow *cwhub.Item) error {
	postoverflowSource, err := filepath.Abs(filepath.Join(t.HubPath, hubPostOverflow.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %s", postoverflowSource, err)
	}

	postoverflowFileName := filepath.Base(postoverflowSource)

	// runtime/hub/postoverflows/s00-enrich/crowdsecurity/
	hubDirPostoverflowDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubPostOverflow.RemotePath))

	// runtime/postoverflows/s00-enrich
	postoverflowDirDest := fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, hubPostOverflow.Stage)

	if err := os.MkdirAll(hubDirPostoverflowDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %s", hubDirPostoverflowDest, err)
	}

	if err := os.MkdirAll(postoverflowDirDest, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %s", postoverflowDirDest, err)
	}

	// runtime/hub/postoverflows/s00-enrich/crowdsecurity/rdns.yaml
	hubDirPostoverflowPath := filepath.Join(hubDirPostoverflowDest, postoverflowFileName)
	if err := Copy(postoverflowSource, hubDirPostoverflowPath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %s", postoverflowSource, hubDirPostoverflowPath, err)
	}

	// runtime/postoverflows/s00-enrich/rdns.yaml
	postoverflowDirParserPath := filepath.Join(postoverflowDirDest, postoverflowFileName)
	if err := os.Symlink(hubDirPostoverflowPath, postoverflowDirParserPath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink postoverflow '%s' to '%s': %s", hubDirPostoverflowPath, postoverflowDirParserPath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installPostoverflowCustom(postoverflow string) error {
	customPostoverflowExist := false
	for _, customPath := range t.CustomItemsLocation {
		// we check if its a custom postoverflow
		customPostOverflowPath := filepath.Join(customPath, postoverflow)
		if _, err := os.Stat(customPostOverflowPath); os.IsNotExist(err) {
			continue
			//return fmt.Errorf("postoverflow '%s' doesn't exist in the hub and doesn't appear to be a custom one.", postoverflow)
		}

		customPostOverflowPathSplit := strings.Split(customPostOverflowPath, "/")
		customPostoverflowName := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-1]
		// because path is postoverflows/<stage>/<author>/parser.yaml and we wan't the stage
		customPostoverflowStage := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-3]

		// check if stage exist
		hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("postoverflows/%s", customPostoverflowStage))

		if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
			continue
			//return fmt.Errorf("stage '%s' from extracted '%s' doesn't exist in the hub", customPostoverflowStage, hubStagePath)
		}

		postoverflowDirDest := fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, customPostoverflowStage)
		if err := os.MkdirAll(postoverflowDirDest, os.ModePerm); err != nil {
			continue
			//return fmt.Errorf("unable to create folder '%s': %s", postoverflowDirDest, err)
		}

		customPostoverflowDest := filepath.Join(postoverflowDirDest, customPostoverflowName)
		// if path to postoverflow exist, copy it
		if err := Copy(customPostOverflowPath, customPostoverflowDest); err != nil {
			continue
			//return fmt.Errorf("unable to copy custom parser '%s' to '%s': %s", customPostOverflowPath, customPostoverflowDest, err)
		}
		customPostoverflowExist = true
		break
	}
	if !customPostoverflowExist {
		return fmt.Errorf("couldn't find custom postoverflow '%s' in the following location: %+v", postoverflow, t.CustomItemsLocation)
	}

	return nil
}

func (t *HubTestItem) installPostoverflow(name string) error {
	if hubPostOverflow := t.HubIndex.GetItem(cwhub.POSTOVERFLOWS, name); hubPostOverflow != nil {
		return t.installPostoverflowItem(hubPostOverflow)
	}

	return t.installPostoverflowCustom(name)
}
