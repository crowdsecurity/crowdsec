package main

import (
	"io"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

func getAgentsTable(out io.Writer, machines []*ent.Machine) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Name", "IP Address", "Last Update", "Status", "Version", "Auth Type", "Last Heartbeat"})

	for _, w := range machines {
		var validated string
		if w.IsValidated {
			validated = emoji.CheckMark.String()
		} else {
			validated = emoji.Prohibited.String()
		}
		table.Append([]string{w.MachineId, w.IpAddress, w.UpdatedAt.Format(time.RFC3339), validated, w.Version, w.AuthType, displayLastHeartBeat(w, true)})
	}

	table.Render()
}
