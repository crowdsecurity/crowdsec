package clinotifications

import (
	"io"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

func notificationListTable(out io.Writer, wantColor string, ncfgs map[string]NotificationsCfg) {
	t := cstable.NewLight(out, wantColor)
	t.SetHeaders("Active", "Name", "Type", "Profile name")
	t.SetHeaderAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

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

		active := emoji.CheckMark
		if len(profilesList) == 0 {
			active = emoji.Prohibited
		}

		t.AddRow(active, b.Config.Name, b.Config.Type, strings.Join(profilesList, ", "))
	}

	t.Render()
}
