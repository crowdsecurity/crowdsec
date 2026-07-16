package clihub

import (
	"fmt"
	"io"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

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

func appendItemRow(t table.Writer, item *cwhub.Item, namePrefix string, showDesc bool) {
	status := fmt.Sprintf("%v  %s", item.State.Emoji(), item.State.Status())
	row := table.Row{item.Type, namePrefix + item.Name, status, item.State.LocalVersion, itemDetails(item)}

	if showDesc {
		row = append(row, strings.TrimSpace(item.Description))
	}

	t.AppendRow(row)
}

// appendItemTree appends an item row and, for a tainted collection, its tainted sub-items
// (from State.TaintedBy) as indented child rows.
func appendItemTree(t table.Writer, hub *cwhub.Hub, item *cwhub.Item, showDesc bool) {
	appendItemRow(t, item, "", showDesc)

	if item.Type != cwhub.COLLECTIONS || item.State.Status() != cwhub.StatusTainted {
		return
	}

	for _, fq := range item.State.TaintedBy {
		if fq == item.FQName() {
			continue
		}

		sub, err := hub.GetItemFQ(fq)
		if err != nil || sub == nil {
			continue
		}

		appendItemRow(t, sub, "  └─ ", showDesc)
	}
}

// taintChildFQNames returns the set of sub-items that will be shown indented under a tainted
// collection, so they are not also rendered as top-level rows.
func taintChildFQNames(items []*cwhub.Item) map[string]bool {
	asChild := make(map[string]bool)

	for _, item := range items {
		if item.Type == cwhub.COLLECTIONS && item.State.Status() == cwhub.StatusTainted {
			for _, fq := range item.State.TaintedBy {
				if fq != item.FQName() {
					asChild[fq] = true
				}
			}
		}
	}

	return asChild
}

// listHubItemCompactTable renders a single flat table across all item types.
// A tainted collection expands its culprit sub-items as indented child rows.
func listHubItemCompactTable(out io.Writer, hub *cwhub.Hub, wantColor string, items []*cwhub.Item, showDesc bool) {
	t := cstable.NewLight(out, wantColor).Writer
	t.AppendHeader(hubTableHeader(showDesc))

	asChild := taintChildFQNames(items)

	for _, item := range items {
		if asChild[item.FQName()] {
			continue
		}

		appendItemTree(t, hub, item, showDesc)
	}

	fmt.Fprintln(out, t.Render())
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

// collectionRows returns the rows for a collection subtree: the collection itself, its installed
// sub-collections (recursively), and its tainted direct sub-items. Non-tainted leaf sub-items are
// only counted in the Details column.
func collectionRows(hub *cwhub.Hub, item *cwhub.Item, depth int, statuses []string, seen map[string]bool) []overviewRow {
	if seen[item.FQName()] {
		return nil
	}

	seen[item.FQName()] = true

	var children []overviewRow

	for sub := range item.CurrentDependencies().SubItems(hub) {
		if !sub.State.IsInstalled() {
			continue
		}

		if sub.Type == cwhub.COLLECTIONS {
			children = append(children, collectionRows(hub, sub, depth+1, statuses, seen)...)
			continue
		}

		if sub.State.Status() == cwhub.StatusTainted && itemMatchesStatus(sub, statuses) {
			children = append(children, overviewRow{sub, depth + 1})
		}
	}

	if len(children) == 0 && !itemMatchesStatus(item, statuses) {
		return nil
	}

	return append([]overviewRow{{item, depth}}, children...)
}

// listHubOverviewTable renders the default "cscli hub list" view: a tree of relevant installed items
func listHubOverviewTable(out io.Writer, hub *cwhub.Hub, wantColor string, roots, standalone []*cwhub.Item, statuses []string) {
	seen := make(map[string]bool)

	var rows []overviewRow
	for _, root := range roots {
		rows = append(rows, collectionRows(hub, root, 0, statuses, seen)...)
	}

	if len(rows) == 0 && len(standalone) == 0 {
		fmt.Fprintln(out, "No items to display")
		return
	}

	t := cstable.NewLight(out, wantColor).Writer
	t.AppendHeader(hubTableHeader(false))

	for _, row := range rows {
		appendItemRow(t, row.item, treePrefix(row.depth), false)
	}

	if len(rows) > 0 && len(standalone) > 0 {
		t.AppendSeparator()
	}

	for _, item := range standalone {
		appendItemRow(t, item, "", false)
	}

	fmt.Fprintln(out, t.Render())
}
