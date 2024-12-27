package cliitem

import (
	"fmt"
	"slices"
	"strings"

	"github.com/agext/levenshtein"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// suggestNearestMessage returns a message with the most similar item name, if one is found
func suggestNearestMessage(hub *cwhub.Hub, itemType string, itemName string) string {
	const maxDistance = 7

	score := 100
	nearest := ""

	for _, item := range hub.GetItemsByType(itemType, false) {
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

func compAllItems(itemType string, args []string, toComplete string, cfg configGetter) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(cfg(), nil)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	comp := make([]string, 0)

	for _, item := range hub.GetItemsByType(itemType, false) {
		if !slices.Contains(args, item.Name) && strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}

	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)

	return comp, cobra.ShellCompDirectiveNoFileComp
}

func compInstalledItems(itemType string, args []string, toComplete string, cfg configGetter) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(cfg(), nil)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	items := hub.GetInstalledByType(itemType, true)

	comp := make([]string, 0)

	for _, item := range items {
		if strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}

	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)

	return comp, cobra.ShellCompDirectiveNoFileComp
}
