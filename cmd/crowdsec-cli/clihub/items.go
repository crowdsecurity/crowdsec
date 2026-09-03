package clihub

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// selectItems returns a slice of items of a given type, selected by name and sorted by case-insensitive name
func SelectItems(hub *cwhub.Hub, itemType string, args []string, installedOnly bool) ([]*cwhub.Item, error) {
	allItems := hub.GetItemsByType(itemType, true)

	itemNames := make([]string, len(allItems))
	for idx, item := range allItems {
		itemNames[idx] = item.Name
	}

	notExist := []string{}

	if len(args) > 0 {
		for _, arg := range args {
			if !slices.Contains(itemNames, arg) {
				notExist = append(notExist, arg)
			}
		}
	}

	if len(notExist) > 0 {
		return nil, fmt.Errorf("item(s) '%s' not found in %s", strings.Join(notExist, ", "), itemType)
	}

	if len(args) > 0 {
		itemNames = args
		installedOnly = false
	}

	wantedItems := make([]*cwhub.Item, 0, len(itemNames))

	for _, itemName := range itemNames {
		item := hub.GetItem(itemType, itemName)
		if installedOnly && !item.State.IsInstalled() {
			continue
		}

		wantedItems = append(wantedItems, item)
	}

	return wantedItems, nil
}

// validItemStatuses are the accepted values for the --status filter of hub list/search.
var validItemStatuses = []string{"installed", cwhub.StatusNotInstalled, cwhub.StatusUpToDate, cwhub.StatusOutdated, cwhub.StatusTainted, cwhub.StatusLocal}

// validateStatuses returns an error if a token is not a recognized status filter.
func validateStatuses(statuses []string) error {
	for _, s := range statuses {
		if !slices.Contains(validItemStatuses, s) {
			return fmt.Errorf("invalid status %q (valid values: %s)", s, strings.Join(validItemStatuses, ", "))
		}
	}

	return nil
}

// itemMatchesStatus reports whether an item's local state matches any of the given status tokens.
// An empty list matches everything. All tokens except "installed" map to a cwhub.Status* word.
func itemMatchesStatus(item *cwhub.Item, statuses []string) bool {
	if len(statuses) == 0 {
		return true
	}

	for _, s := range statuses {
		if s == "installed" {
			if item.State.IsInstalled() {
				return true
			}

			continue
		}

		if item.State.Status() == s {
			return true
		}
	}

	return false
}

// filterItemsByStatus returns the items whose state matches any of the given status tokens.
func filterItemsByStatus(items []*cwhub.Item, statuses []string) []*cwhub.Item {
	if len(statuses) == 0 {
		return items
	}

	ret := make([]*cwhub.Item, 0, len(items))

	for _, item := range items {
		if itemMatchesStatus(item, statuses) {
			ret = append(ret, item)
		}
	}

	return ret
}

// itemsByType returns installed items grouped by type (or every item when all is true), each
// group filtered by the given status tokens.
func itemsByType(hub *cwhub.Hub, all bool, statuses []string) (map[string][]*cwhub.Item, error) {
	items := make(map[string][]*cwhub.Item)

	for _, itemType := range cwhub.ItemTypes {
		selected, err := SelectItems(hub, itemType, nil, !all)
		if err != nil {
			return nil, err
		}

		items[itemType] = filterItemsByStatus(selected, statuses)
	}

	return items, nil
}

func ListItems(out io.Writer, wantColor string, itemTypes []string, items map[string][]*cwhub.Item, omitIfEmpty bool, output string) error {
	switch output {
	case "human":
		nothingToDisplay := true

		for _, itemType := range itemTypes {
			if omitIfEmpty && len(items[itemType]) == 0 {
				continue
			}

			listHubItemTable(out, wantColor, strings.ToUpper(itemType), items[itemType])

			nothingToDisplay = false
		}

		if nothingToDisplay {
			fmt.Fprintln(os.Stdout, "No items to display")
		}
	case "json":
		type itemHubStatus struct {
			Name         string `json:"name"`
			LocalVersion string `json:"local_version"`
			LocalPath    string `json:"local_path"`
			Description  string `json:"description"`
			UTF8Status   string `json:"utf8_status"`
			Status       string `json:"status"`
		}

		hubStatus := make(map[string][]itemHubStatus)
		for _, itemType := range itemTypes {
			// empty slice in case there are no items of this type
			hubStatus[itemType] = make([]itemHubStatus, len(items[itemType]))

			for i, item := range items[itemType] {
				status := item.State.Text()
				statusEmo := item.State.Emoji()
				hubStatus[itemType][i] = itemHubStatus{
					Name:         item.Name,
					LocalVersion: item.State.LocalVersion,
					LocalPath:    item.State.LocalPath,
					Description:  strings.TrimSpace(item.Description),
					Status:       status,
					UTF8Status:   fmt.Sprintf("%v  %s", statusEmo, status),
				}
			}
		}

		x, err := json.MarshalIndent(hubStatus, "", " ")
		if err != nil {
			return fmt.Errorf("failed to parse: %w", err)
		}

		fmt.Fprint(out, string(x))
	case "raw":
		csvwriter := csv.NewWriter(out)

		header := []string{"name", "status", "version", "description"}
		if len(itemTypes) > 1 {
			header = append(header, "type")
		}

		if err := csvwriter.Write(header); err != nil {
			return fmt.Errorf("failed to write header: %w", err)
		}

		for _, itemType := range itemTypes {
			for _, item := range items[itemType] {
				row := []string{
					item.Name,
					item.State.Text(),
					item.State.LocalVersion,
					strings.TrimSpace(item.Description),
				}
				if len(itemTypes) > 1 {
					row = append(row, itemType)
				}

				if err := csvwriter.Write(row); err != nil {
					return fmt.Errorf("failed to write raw output: %w", err)
				}
			}
		}

		csvwriter.Flush()
	}

	return nil
}
