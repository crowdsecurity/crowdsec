package clihub

import (
	"fmt"
	"io"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

// dimColor is the faint style used for secondary info (tree markers, type, details).
var dimColor = text.Colors{text.FgHiBlack}

// 256-color codes for shades not in the basic 16-color ANSI set.
const (
	color256Limeade = 154 // yellow-green
	color256Orange  = 208
)

// statusColor maps a status word to its palette, tracking the status emoji.
func statusColor(status string) text.Colors {
	switch status {
	case cwhub.StatusUpToDate:
		return text.Colors{text.FgGreen}
	case cwhub.StatusOutdated:
		return text.Colors{text.Fg256Color(color256Limeade)}
	case cwhub.StatusTainted:
		return text.Colors{text.Fg256Color(color256Orange), text.Bold}
	case cwhub.StatusLocal:
		return text.Colors{text.FgCyan}
	case cwhub.StatusNotInstalled:
		return text.Colors{text.FgHiBlack}
	default:
		return nil
	}
}

func listHubItemTable(out io.Writer, wantColor string, title string, items []*cwhub.Item) {
	t := cstable.NewLight(out, wantColor).Writer
	t.AppendHeader(table.Row{"Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path"})

	for _, item := range items {
		status := fmt.Sprintf("%v  %s", item.State.Emoji(), item.State.Text())
		t.AppendRow(table.Row{item.Name, status, item.State.LocalVersion, item.State.LocalPath})
	}

	t.SetTitle(title)
	fmt.Fprintln(out, t.Render())
}

// collectionSummary returns a short count of a collection's contents, eg. "2 parser(s) / 3 scenario(s)".
func collectionSummary(item *cwhub.Item) string {
	groups := item.ByType()

	parts := make([]string, 0, len(groups))

	for _, g := range groups {
		if len(g.Names) > 0 {
			label := strings.TrimSuffix(g.Type, "s") + "(s)"
			parts = append(parts, fmt.Sprintf("%d %s", len(g.Names), label))
		}
	}

	return strings.Join(parts, " / ")
}

// itemDetails returns the rightmost column: for collections a content summary (with the version
// delta prepended when outdated), for leaf items a short status reason.
func itemDetails(item *cwhub.Item) string {
	if item.Type == cwhub.COLLECTIONS {
		summary := collectionSummary(item)
		if item.State.Status() != cwhub.StatusOutdated {
			return summary
		}

		delta := fmt.Sprintf("%s → %s", item.State.LocalVersion, item.Version)
		if summary == "" {
			return delta
		}

		return delta + " · " + summary
	}

	switch item.State.Status() {
	case cwhub.StatusTainted:
		// only collections inherit taint, so a tainted leaf was edited directly
		return "edited locally"
	case cwhub.StatusOutdated:
		return fmt.Sprintf("%s → %s", item.State.LocalVersion, item.Version)
	default:
		return ""
	}
}

func hubTableHeader(showDesc bool) table.Row {
	header := table.Row{"Type", "Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Details"}
	if showDesc {
		header = append(header, "Description")
	}

	return header
}

func appendItemRow(t table.Writer, item *cwhub.Item, namePrefix string, showDesc, colorize bool) {
	statusWord := item.State.Status()
	name := item.Name
	itemType := item.Type
	prefix := namePrefix
	details := itemDetails(item)

	if colorize {
		statusWord = statusColor(statusWord).Sprint(statusWord)
		if item.Type == cwhub.COLLECTIONS {
			name = text.Bold.Sprint(name)
		}

		if prefix != "" {
			prefix = dimColor.Sprint(prefix)
		}

		itemType = dimColor.Sprint(itemType)

		if details != "" {
			details = dimColor.Sprint(details)
		}
	}

	status := fmt.Sprintf("%v  %s", item.State.Emoji(), statusWord)
	row := table.Row{itemType, prefix + name, status, item.State.LocalVersion, details}

	if showDesc {
		row = append(row, strings.TrimSpace(item.Description))
	}

	t.AppendRow(row)
}

func treePrefix(depth int) string {
	if depth == 0 {
		return ""
	}

	return strings.Repeat("  ", depth) + "└─ "
}

type overviewRow struct {
	item  *cwhub.Item
	depth int
}

// treeRows flattens an installed-item node into display rows, applying view policy: a collection
// always shows; a leaf shows only when full or tainted, and must match the status filter; a
// collection with no shown children and a non-matching status is omitted.
func treeRows(node *cwhub.ItemNode, depth int, statuses []string, full bool) []overviewRow {
	var children []overviewRow

	for _, child := range node.Children {
		if child.Item.Type == cwhub.COLLECTIONS {
			children = append(children, treeRows(child, depth+1, statuses, full)...)
			continue
		}

		if (full || child.Item.State.Status() == cwhub.StatusTainted) && itemMatchesStatus(child.Item, statuses) {
			children = append(children, overviewRow{child.Item, depth + 1})
		}
	}

	if len(children) == 0 && !itemMatchesStatus(node.Item, statuses) {
		return nil
	}

	return append([]overviewRow{{node.Item, depth}}, children...)
}

// flatRows turns a flat list of items into depth-0 rows for the search / -a views.
func flatRows(items []*cwhub.Item) []overviewRow {
	rows := make([]overviewRow, 0, len(items))
	for _, item := range items {
		rows = append(rows, overviewRow{item, 0})
	}

	return rows
}

// renderItemTable is the single renderer for the tree (list) and flat (-a, search) views.
// A separator is drawn once at the depth-0 collection→non-collection boundary, which only happens
// in the default list view (collections first, then standalone items).
func renderItemTable(out io.Writer, wantColor string, rows []overviewRow, showDesc bool) {
	colorize := cstable.ShouldColorize(wantColor)

	t := cstable.NewLight(out, wantColor).Writer
	t.AppendHeader(hubTableHeader(showDesc))

	afterCollectionRoot := false

	for _, row := range rows {
		if row.depth == 0 && afterCollectionRoot && row.item.Type != cwhub.COLLECTIONS {
			t.AppendSeparator()

			afterCollectionRoot = false
		}

		appendItemRow(t, row.item, treePrefix(row.depth), showDesc, colorize)

		if row.depth == 0 && row.item.Type == cwhub.COLLECTIONS {
			afterCollectionRoot = true
		}
	}

	fmt.Fprintln(out, t.Render())
}
