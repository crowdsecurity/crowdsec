package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func ListItems(out io.Writer, itemTypes []string, args []string, showType bool, showHeader bool, all bool) {
	var hubStatusByItemType = make(map[string][]ItemHubStatus)

	for _, itemType := range itemTypes {
		itemName := ""
		if len(args) == 1 {
			itemName = args[0]
		}
		hubStatusByItemType[itemType] = GetHubStatusForItemType(itemType, itemName, all)
	}

	if csConfig.Cscli.Output == "human" {
		for _, itemType := range itemTypes {
			var statuses []ItemHubStatus
			var ok bool
			if statuses, ok = hubStatusByItemType[itemType]; !ok {
				log.Errorf("unknown item type: %s", itemType)
				continue
			}
			listHubItemTable(out, "\n"+strings.ToUpper(itemType), statuses)
		}
	} else if csConfig.Cscli.Output == "json" {
		x, err := json.MarshalIndent(hubStatusByItemType, "", " ")
		if err != nil {
			log.Fatalf("failed to unmarshal")
		}
		out.Write(x)
	} else if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(out)
		if showHeader {
			header := []string{"name", "status", "version", "description"}
			if showType {
				header = append(header, "type")
			}
			err := csvwriter.Write(header)
			if err != nil {
				log.Fatalf("failed to write header: %s", err)
			}

		}
		for _, itemType := range itemTypes {
			var statuses []ItemHubStatus
			var ok bool
			if statuses, ok = hubStatusByItemType[itemType]; !ok {
				log.Errorf("unknown item type: %s", itemType)
				continue
			}
			for _, status := range statuses {
				if status.LocalVersion == "" {
					status.LocalVersion = "n/a"
				}
				row := []string{
					status.Name,
					status.Status,
					status.LocalVersion,
					status.Description,
				}
				if showType {
					row = append(row, itemType)
				}
				err := csvwriter.Write(row)
				if err != nil {
					log.Fatalf("failed to write raw output : %s", err)
				}
			}
		}
		csvwriter.Flush()
	}
}

func InspectItem(name string, itemType string, noMetrics bool) error {
	hubItem := cwhub.GetItem(itemType, name)
	if hubItem == nil {
		return fmt.Errorf("can't find '%s' in %s", name, itemType)
	}

	var (
		b   []byte
		err error
	)

	switch csConfig.Cscli.Output {
	case "human", "raw":
		b, err = yaml.Marshal(*hubItem)
		if err != nil {
			return fmt.Errorf("unable to marshal item: %s", err)
		}
	case "json":
		b, err = json.MarshalIndent(*hubItem, "", " ")
		if err != nil {
			return fmt.Errorf("unable to marshal item: %s", err)
		}
	}

	fmt.Printf("%s", string(b))

	if noMetrics || csConfig.Cscli.Output == "json" || csConfig.Cscli.Output == "raw" {
		return nil
	}

	if prometheusURL == "" {
		// This is technically wrong to do this, as the prometheus section contains a listen address, not an URL to query prometheus
		// But for ease of use, we will use the listen address as the prometheus URL because it will be 127.0.0.1 in the default case
		listenAddr := csConfig.Prometheus.ListenAddr
		listenPort := csConfig.Prometheus.ListenPort
		prometheusURL = fmt.Sprintf("http://%s:%d/metrics", listenAddr, listenPort)
		log.Debugf("No prometheus URL provided using: %s", prometheusURL)
	}

	fmt.Printf("\nCurrent metrics: \n")
	ShowMetrics(hubItem)

	return nil
}

// ItemHubStatus is used to display the status of an item
type ItemHubStatus struct {
	Name         string `json:"name"`
	LocalVersion string `json:"local_version"`
	LocalPath    string `json:"local_path"`
	Description  string `json:"description"`
	UTF8Status   string `json:"utf8_status"`
	Status       string `json:"status"`
}

func hubStatus(i cwhub.Item) ItemHubStatus {
	status, emo := i.Status()

	return ItemHubStatus{
		Name:         i.Name,
		LocalVersion: i.LocalVersion,
		LocalPath:    i.LocalPath,
		Description:  i.Description,
		Status:       status,
		UTF8Status:   fmt.Sprintf("%v  %s", emo, status),
	}
}

// Returns a slice of entries for packages: name, status, local_path, local_version, utf8_status (fancy)
func GetHubStatusForItemType(itemType string, name string, all bool) []ItemHubStatus {
	items := cwhub.GetItemMap(itemType)
	if items == nil {
		log.Errorf("type %s doesn't exist", itemType)

		return nil
	}

	ret := make([]ItemHubStatus, 0)

	// remember, you do it for the user :)
	for _, item := range items {
		if name != "" && name != item.Name {
			// user has requested a specific name
			continue
		}

		// Only enabled items ?
		if !all && !item.Installed {
			continue
		}
		// Check the item status
		ret = append(ret, hubStatus(item))
	}

	sort.Slice(ret, func(i, j int) bool { return ret[i].Name < ret[j].Name })

	return ret
}
