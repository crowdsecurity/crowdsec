package main

import (
	"io"
	"time"

	"github.com/aquasecurity/table"
	"github.com/enescakir/emoji"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func getAgentsTable(out io.Writer, machines []*ent.Machine) {
	t := newLightTable(out)
	t.SetHeaders("Name", "IP Address", "Last Update", "Status", "Version", "Auth Type", "Last Heartbeat")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	for _, m := range machines {
		var validated string
		if m.IsValidated {
			validated = emoji.CheckMark.String()
		} else {
			validated = emoji.Prohibited.String()
		}

		hb, active := getLastHeartbeat(m)
		if !active {
			hb = emoji.Warning.String() + " " + hb
		}
		t.AddRow(m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, m.AuthType, hb)
	}

	t.Render()
}
