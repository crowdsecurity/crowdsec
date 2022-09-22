package main

import (
	"io"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

func getBouncersTable(out io.Writer, bouncers []*ent.Bouncer) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Name", "IP Address", "Valid", "Last API pull", "Type", "Version", "Auth Type"})

	for _, b := range bouncers {
		var revoked string
		if !b.Revoked {
			revoked = emoji.CheckMark.String()
		} else {
			revoked = emoji.Prohibited.String()
		}

		table.Append([]string{b.Name, b.IPAddress, revoked, b.LastPull.Format(time.RFC3339), b.Type, b.Version, b.AuthType})
	}

	table.Render()
}
