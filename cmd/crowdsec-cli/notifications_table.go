package main

import (
	"io"
	"sort"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/enescakir/emoji"
)

func notificationListTable(out io.Writer, ncfgs map[string]NotificationsCfg) {
	t := newLightTable(out)
	t.SetHeaders("Active", "Name", "Type", "Profile name")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)
	keys := make([]string, 0, len(ncfgs))
	for k := range ncfgs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(ncfgs[keys[i]].Profiles) > len(ncfgs[keys[j]].Profiles)
	})
	for _, k := range keys {
		b := ncfgs[k]
		profilesList := []string{}
		for _, p := range b.Profiles {
			profilesList = append(profilesList, p.Name)
		}
		active := emoji.CheckMark.String()
		if len(profilesList) == 0 {
			active = emoji.Prohibited.String()
		}
		t.AddRow(active, b.Config.Name, b.Config.Type, strings.Join(profilesList, ", "))
	}
	t.Render()
}
