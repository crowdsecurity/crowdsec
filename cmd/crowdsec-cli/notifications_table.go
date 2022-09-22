package main

import (
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"
)

func notificationListTable(out io.Writer, ncfgs map[string]NotificationsCfg) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Name", "Type", "Profile name"})

	for _, b := range ncfgs {
		profilesList := []string{}
		for _, p := range b.Profiles {
			profilesList = append(profilesList, p.Name)
		}
		table.Append([]string{b.Config.Name, b.Config.Type, strings.Join(profilesList, ", ")})
	}

	table.Render()
}
