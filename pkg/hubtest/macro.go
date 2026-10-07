package hubtest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (t *HubTestItem) installMacroItem(item *cwhub.Item) error {
	sourcePath, err := filepath.Abs(filepath.Join(t.HubPath, item.RemotePath))
	if err != nil {
		return fmt.Errorf("can't get absolute path of '%s': %w", sourcePath, err)
	}

	sourceFilename := filepath.Base(sourcePath)

	// runtime/hub/macros/crowdsecurity/
	hubDirMacroDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(item.RemotePath))

	// runtime/macros/
	itemTypeDirDest := fmt.Sprintf("%s/macros/", t.RuntimePath)

	if err := createDirs([]string{hubDirMacroDest, itemTypeDirDest}); err != nil {
		return err
	}

	// runtime/hub/macros/crowdsecurity/http-macros.yaml
	hubDirMacroPath := filepath.Join(hubDirMacroDest, sourceFilename)
	if err := Copy(sourcePath, hubDirMacroPath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %w", sourcePath, hubDirMacroPath, err)
	}

	// runtime/macros/http-macros.yaml
	macroDirPath := filepath.Join(itemTypeDirDest, sourceFilename)
	if err := os.Symlink(hubDirMacroPath, macroDirPath); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to symlink macro '%s' to '%s': %w", hubDirMacroPath, macroDirPath, err)
		}
	}

	return nil
}

func (t *HubTestItem) installMacroCustomFrom(macro string, customPath string) (bool, error) {
	// we check if its a custom macro
	customMacroPath := filepath.Join(customPath, macro)
	if _, err := os.Stat(customMacroPath); os.IsNotExist(err) {
		return false, nil
	}

	itemTypeDirDest := fmt.Sprintf("%s/macros/", t.RuntimePath)
	if err := os.MkdirAll(itemTypeDirDest, os.ModePerm); err != nil {
		return false, fmt.Errorf("unable to create folder '%s': %w", itemTypeDirDest, err)
	}

	macroFileName := filepath.Base(customMacroPath)

	macroFileDest := filepath.Join(itemTypeDirDest, macroFileName)
	if err := Copy(customMacroPath, macroFileDest); err != nil {
		return false, fmt.Errorf("unable to copy macro from '%s' to '%s': %w", customMacroPath, macroFileDest, err)
	}

	return true, nil
}

func (t *HubTestItem) installMacroCustom(macro string) error {
	for _, customPath := range t.CustomItemsLocation {
		found, err := t.installMacroCustomFrom(macro, customPath)
		if err != nil {
			return err
		}

		if found {
			return nil
		}
	}

	return fmt.Errorf("couldn't find custom macro '%s' in the following location: %+v", macro, t.CustomItemsLocation)
}

func (t *HubTestItem) installMacro(name string) error {
	if item := t.HubIndex.GetItem(cwhub.MACROS, name); item != nil {
		return t.installMacroItem(item)
	}

	return t.installMacroCustom(name)
}
