package main

import (
	"fmt"
	"io"
	"time"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/table"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/jedib0t/go-pretty/v6/text"
)

var tableHeaders = []string{"Name", "IP Address", "Last Update", "Status", "Version", "OS", "Auth Type", "Feature Flags", "Last Heartbeat"}

func getAgentsTable(out io.Writer, machines []*ent.Machine) {
	t := newLightTable(out)
	t.SetHeaders(tableHeaders...)

	alignment := []text.Align{}

	for i := 0; i < len(tableHeaders); i++ {
		alignment = append(alignment, table.AlignLeft)
	}

	t.SetHeaderAlignment(alignment...)
	t.SetAlignment(alignment...)

	for _, m := range machines {
		validated := emoji.Prohibited
		if m.IsValidated {
			validated = emoji.CheckMark
		}

		hb, active := getLastHeartbeat(m)
		if !active {
			hb = emoji.Warning + " " + hb
		}

		t.AddRow(m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, fmt.Sprintf("%s/%s", m.Osname, m.Osversion), m.AuthType, m.Featureflags, hb)
	}

	t.Render()
}
