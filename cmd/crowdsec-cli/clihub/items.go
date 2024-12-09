package clihub

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

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
		if installedOnly && !item.State.Installed {
			continue
		}

		wantedItems = append(wantedItems, item)
	}

	return wantedItems, nil
}

func ListItems(out io.Writer, wantColor string, itemTypes []string, items map[string][]*cwhub.Item, omitIfEmpty bool, output string) error {
	switch output {
	case "human":
		nothingToDisplay := true

		for _, itemType := range itemTypes {
			if omitIfEmpty && len(items[itemType]) == 0 {
				continue
			}

			listHubItemTable(out, wantColor, "\n"+strings.ToUpper(itemType), items[itemType])

			nothingToDisplay = false
		}

		if nothingToDisplay {
			fmt.Println("No items to display")
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

		out.Write(x)
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

func InspectItem(item *cwhub.Item, wantMetrics bool, output string, prometheusURL string, wantColor string) error {
	switch output {
	case "human", "raw":
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)

		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("unable to encode item: %w", err)
		}
	case "json":
		b, err := json.MarshalIndent(*item, "", "  ")
		if err != nil {
			return fmt.Errorf("unable to serialize item: %w", err)
		}

		fmt.Print(string(b))
	}

	if output != "human" {
		return nil
	}

	if item.State.Tainted {
		fmt.Println()
		fmt.Printf(`This item is tainted. Use "%s %s inspect --diff %s" to see why.`, filepath.Base(os.Args[0]), item.Type, item.Name)
		fmt.Println()
	}

	if wantMetrics {
		fmt.Printf("\nCurrent metrics: \n")

		if err := showMetrics(prometheusURL, item, wantColor); err != nil {
			return err
		}
	}

	return nil
}
