package cwhub

// Resolve a symlink to find the hub item it points to.
// This file is used only by pkg/leakybucket

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// itemKey extracts the map key of an item (i.e. author/name) from its pathname. Follows a symlink if necessary.
func itemKey(itemPath string) (string, error) {
	f, err := os.Lstat(itemPath)
	if err != nil {
		return "", fmt.Errorf("while performing lstat on %s: %w", itemPath, err)
	}

	if f.Mode()&os.ModeSymlink == 0 {
		// it's not a symlink, so the filename itsef should be the key
		return filepath.Base(itemPath), nil
	}

	// resolve the symlink to hub file
	pathInHub, err := os.Readlink(itemPath)
	if err != nil {
		return "", fmt.Errorf("while reading symlink of %s: %w", itemPath, err)
	}

	author := filepath.Base(filepath.Dir(pathInHub))

	fname := filepath.Base(pathInHub)
	fname = strings.TrimSuffix(fname, ".yaml")
	fname = strings.TrimSuffix(fname, ".yml")

	return fmt.Sprintf("%s/%s", author, fname), nil
}

// GetItemByPath retrieves an item from the hub index based on its local path.
func (h *Hub) GetItemByPath(itemType string, itemPath string) (*Item, error) {
	itemKey, err := itemKey(itemPath)
	if err != nil {
		return nil, err
	}

	item := h.GetItem(itemType, itemKey)
	if item == nil {
		return nil, fmt.Errorf("%s not found in %s", itemKey, itemType)
	}

	return item, nil
}
