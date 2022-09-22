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

	for _, m := range machines {
		var validated string
		if m.IsValidated {
			validated = emoji.CheckMark.String()
		} else {
			validated = emoji.Prohibited.String()
		}

		table.Append([]string{m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, m.AuthType, displayLastHeartBeat(m, true)})
	}

	table.Render()
}
