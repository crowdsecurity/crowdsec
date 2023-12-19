package main

import (
	"fmt"
	"strings"

	"github.com/agext/levenshtein"
	"github.com/spf13/cobra"
	"slices"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// suggestNearestMessage returns a message with the most similar item name, if one is found
func suggestNearestMessage(hub *cwhub.Hub, itemType string, itemName string) string {
	const maxDistance = 7

	score := 100
	nearest := ""

	for _, item := range hub.GetItemMap(itemType) {
		d := levenshtein.Distance(itemName, item.Name, nil)
		if d < score {
			score = d
			nearest = item.Name
		}
	}

	msg := fmt.Sprintf("can't find '%s' in %s", itemName, itemType)

	if score < maxDistance {
		msg += fmt.Sprintf(", did you mean '%s'?", nearest)
	}

	return msg
}

func compAllItems(itemType string, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(csConfig, nil, nil)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	comp := make([]string, 0)

	for _, item := range hub.GetItemMap(itemType) {
		if !slices.Contains(args, item.Name) && strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}

	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)

	return comp, cobra.ShellCompDirectiveNoFileComp
}

func compInstalledItems(itemType string, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(csConfig, nil, nil)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	items, err := hub.GetInstalledItemNames(itemType)
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
