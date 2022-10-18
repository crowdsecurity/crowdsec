package main

import (
	"io"
	"time"

	"github.com/aquasecurity/table"
	"github.com/enescakir/emoji"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func getBouncersTable(out io.Writer, bouncers []*ent.Bouncer) {
	t := newLightTable(out)
	t.SetHeaders("Name", "IP Address", "Valid", "Last API pull", "Type", "Version", "Auth Type")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	for _, b := range bouncers {
		var revoked string
		if !b.Revoked {
			revoked = emoji.CheckMark.String()
		} else {
			revoked = emoji.Prohibited.String()
		}

		t.AddRow(b.Name, b.IPAddress, revoked, b.LastPull.Format(time.RFC3339), b.Type, b.Version, b.AuthType)
	}

	t.Render()
}
