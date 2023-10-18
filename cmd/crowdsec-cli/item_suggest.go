package main

import (
	"fmt"
	"strings"

	"github.com/agext/levenshtein"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"slices"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

const MaxDistance = 7

func Suggest(itemType string, baseItem string, suggestItem string, score int, ignoreErr bool) {
	errMsg := ""
	if score < MaxDistance {
		errMsg = fmt.Sprintf("can't find '%s' in %s, did you mean %s?", baseItem, itemType, suggestItem)
	} else {
		errMsg = fmt.Sprintf("can't find '%s' in %s", baseItem, itemType)
	}
	if ignoreErr {
		log.Error(errMsg)
	} else {
		log.Fatalf(errMsg)
	}
}

func GetDistance(itemType string, itemName string) (*cwhub.Item, int) {
	allItems := make([]string, 0)
	nearestScore := 100
	nearestItem := &cwhub.Item{}

	// XXX: handle error
	hub, _ := cwhub.GetHub()

	hubItems := hub.GetItemMap(itemType)
	for _, item := range hubItems {
		allItems = append(allItems, item.Name)
	}

	for _, s := range allItems {
		d := levenshtein.Distance(itemName, s, nil)
		if d < nearestScore {
			nearestScore = d
			nearestItem = hub.GetItem(itemType, s)
		}
	}
	return nearestItem, nearestScore
}

func compAllItems(itemType string, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(csConfig)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	comp := make([]string, 0)
	hubItems := hub.GetItemMap(itemType)
	for _, item := range hubItems {
		if !slices.Contains(args, item.Name) && strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}
	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)
	return comp, cobra.ShellCompDirectiveNoFileComp
}

func compInstalledItems(itemType string, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(csConfig)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	items, err := hub.GetInstalledItemsAsString(itemType)
	if err != nil {
		cobra.CompDebugln(fmt.Sprintf("list installed %s err: %s", itemType, err), true)
		return nil, cobra.ShellCompDirectiveDefault
	}

	comp := make([]string, 0)

	if toComplete != "" {
		for _, item := range items {
			if strings.Contains(item, toComplete) {
				comp = append(comp, item)
			}
		}
	} else {
		comp = items
	}

	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)

	return comp, cobra.ShellCompDirectiveNoFileComp
}
