package main

import (
	"fmt"
	"io"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

func ctiTable(out io.Writer, item *cticlient.SmokeItem) {
	t := newTable(out)
	t.SetRowLines(false)
	header := []string{"ip", "range", "as", "location", "history", "classification", "attacks"}
	t.SetHeaders(header...)

	countryString := ""
	if item.Location.City != nil {
		countryString = fmt.Sprintf("Country: %s\nCity: %s", *item.Location.Country, *item.Location.City)
	} else {
		countryString = fmt.Sprintf("Country: %s", *item.Location.Country)
	}

	row := []string{
		item.Ip,
		*item.IpRange,
		fmt.Sprintf("Name: %s\nNumber: %d", *item.AsName, *item.AsNum),
		countryString,
		fmt.Sprintf("First Seen: %s\nLast Seen: %s", *item.History.FirstSeen, *item.History.LastSeen),
		classificationToString(item, true),
		attacksToString(item, true),
	}
	t.AddRow(row...)
	t.Render()
}

func classificationToString(item *cticlient.SmokeItem, newLine bool) string {
	output := ""
	if len(item.Classifications.FalsePositives) > 0 {
		output += "False Positives:"
		if newLine {
			output += "\n"
		}
	}
	for _, v := range item.Classifications.FalsePositives {
		output += fmt.Sprintf("- %s", v.Name)
		if newLine {
			output += "\n"
		}
	}
	if len(item.Classifications.Classifications) > 0 {
		if newLine {
			output += "\n"
		}
		output += "Classifications:"
		if newLine {
			output += "\n"
		}
	}
	for _, v := range item.Classifications.Classifications {
		output += fmt.Sprintf("- %s", v.Name)
		if newLine {
			output += "\n"
		}
	}
	return output
}

func attacksToString(item *cticlient.SmokeItem, newLine bool) string {
	output := ""
	if len(item.AttackDetails) > 0 {
		for _, v := range item.AttackDetails {
			output += fmt.Sprintf("- %s", v.Name)
			if newLine {
				output += "\n"
			}
		}
	}
	return output
}
