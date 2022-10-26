package main

import (
	"io"
	"strings"

	"github.com/aquasecurity/table"
)

func notificationListTable(out io.Writer, ncfgs map[string]NotificationsCfg) {
	t := newLightTable(out)
	t.SetHeaders("Name", "Type", "Profile name")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	for _, b := range ncfgs {
		profilesList := []string{}
		for _, p := range b.Profiles {
			profilesList = append(profilesList, p.Name)
		}
		t.AddRow(b.Config.Name, b.Config.Type, strings.Join(profilesList, ", "))
	}

	t.Render()
}
