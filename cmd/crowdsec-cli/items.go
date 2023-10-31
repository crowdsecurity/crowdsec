package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"slices"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func selectItems(hub *cwhub.Hub, itemType string, args []string, installedOnly bool) ([]string, error) {
	itemNames := hub.GetItemNames(itemType)

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

	if installedOnly {
		installed := []string{}
		for _, item := range itemNames {
			if hub.GetItem(itemType, item).Installed {
				installed = append(installed, item)
			}
		}
		return installed, nil
	}
	return itemNames, nil
}

func ListItems(hub *cwhub.Hub, out io.Writer, itemTypes []string, args []string, showType bool, showHeader bool, all bool) error {
	items := make(map[string][]string)
	for _, itemType := range itemTypes {
		selected, err := selectItems(hub, itemType, args, !all)
		if err != nil {
			return err
		}
		sort.Strings(selected)
		items[itemType] = selected
	}

	switch csConfig.Cscli.Output {
	case "human":
		for _, itemType := range itemTypes {
			listHubItemTable(hub, out, "\n"+strings.ToUpper(itemType), itemType, items[itemType])
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
			for i, itemName := range items[itemType] {
				item := hub.GetItem(itemType, itemName)
				status, emo := item.Status()
				hubStatus[itemType][i] = itemHubStatus{
					Name:         item.Name,
					LocalVersion: item.LocalVersion,
					LocalPath:    item.LocalPath,
					Description:  item.Description,
					Status:       status,
					UTF8Status:   fmt.Sprintf("%v  %s", emo, status),
				}
			}
		}
		x, err := json.MarshalIndent(hubStatus, "", " ")
		if err != nil {
			return fmt.Errorf("failed to unmarshal: %w", err)
		}
		out.Write(x)
	case "raw":
		csvwriter := csv.NewWriter(out)

		if showHeader {
			header := []string{"name", "status", "version", "description"}
			if showType {
				header = append(header, "type")
			}
			err := csvwriter.Write(header)
			if err != nil {
				return fmt.Errorf("failed to write header: %s", err)
			}
		}
		for _, itemType := range itemTypes {
			for _, itemName := range items[itemType] {
				item := hub.GetItem(itemType, itemName)
				status, _ := item.Status()
				if item.LocalVersion == "" {
					item.LocalVersion = "n/a"
				}
				row := []string{
					item.Name,
					status,
					item.LocalVersion,
					item.Description,
				}
				if showType {
					row = append(row, itemType)
				}
				if err := csvwriter.Write(row); err != nil {
					return fmt.Errorf("failed to write raw output: %s", err)
				}
			}
		}
		csvwriter.Flush()
	default:
		return fmt.Errorf("unknown output format '%s'", csConfig.Cscli.Output)
	}

	return nil
}

func InspectItem(hub *cwhub.Hub, item *cwhub.Item, showMetrics bool) error {
	switch csConfig.Cscli.Output {
	case "human", "raw":
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)
		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("unable to encode item: %s", err)
		}
	case "json":
		b, err := json.MarshalIndent(*item, "", "  ")
		if err != nil {
			return fmt.Errorf("unable to marshal item: %s", err)
		}
		fmt.Print(string(b))
	}

	if csConfig.Cscli.Output == "human" && showMetrics {
		fmt.Printf("\nCurrent metrics: \n")
		ShowMetrics(hub, item)
	}

	return nil
}
