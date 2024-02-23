package main

import (
	"io"
	"time"

	"github.com/aquasecurity/table"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

func getAgentsTable(out io.Writer, machines []*ent.Machine) {
	t := newLightTable(out)
	t.SetHeaders("Name", "IP Address", "Last Update", "Status", "Version", "Auth Type", "Last Heartbeat")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	for _, m := range machines {
		validated := emoji.Prohibited
		if m.IsValidated {
			validated = emoji.CheckMark
		}

		hb, active := getLastHeartbeat(m)
		if !active {
			hb = emoji.Warning + " " + hb
		}

		t.AddRow(m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, m.AuthType, hb)
	}

	t.Render()
}
