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
	groups := item.CurrentDependencies().ByType()

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

type overviewRow struct {
	item   *cwhub.Item
	depth  int
	prefix string // tree branch drawing (├─/└─ with │ guides); empty for depth-0 rows
}

// leafShown reports whether a non-collection leaf renders as its own row: it must match the status
// filter, and then only when --full, a status filter is active, or it is tainted.
func leafShown(item *cwhub.Item, statuses []string, full bool) bool {
	return itemMatchesStatus(item, statuses) &&
		(full || len(statuses) > 0 || item.State.Status() == cwhub.StatusTainted)
}

// treeRows flattens an installed-item node into display rows, applying view policy: a collection
// always shows; a leaf shows only when full or tainted, and must match the status filter; a
// collection with no shown children and a non-matching status is omitted. Each nested row carries a
// ├─/└─ branch marker, with │ guides connecting an ancestor to its siblings further down.
func treeRows(node *cwhub.ItemNode, depth int, statuses []string, full bool) []overviewRow {
	// render each visible direct child as its own subtree, with prefixes relative to that child;
	// the branch marker and guides are prepended below, once we know which child is last.
	var childSubtrees [][]overviewRow

	for _, child := range node.Children {
		if child.Item.Type == cwhub.COLLECTIONS {
			if sub := treeRows(child, depth+1, statuses, full); len(sub) > 0 {
				childSubtrees = append(childSubtrees, sub)
			}

			continue
		}

		if leafShown(child.Item, statuses, full) {
			childSubtrees = append(childSubtrees, []overviewRow{{item: child.Item, depth: depth + 1}})
		}
	}

	if len(childSubtrees) == 0 && !itemMatchesStatus(node.Item, statuses) {
		return nil
	}

	rows := []overviewRow{{item: node.Item, depth: depth}}

	for i, sub := range childSubtrees {
		branch, guide := "├─ ", "│  "
		if i == len(childSubtrees)-1 {
			branch, guide = "└─ ", "   "
		}

		for j := range sub {
			if j == 0 {
				sub[j].prefix = branch + sub[j].prefix
			} else {
				sub[j].prefix = guide + sub[j].prefix
			}

			rows = append(rows, sub[j])
		}
	}

	return rows
}

// placedInTree collects the FQNames of every item present in the installed-item forest, so
// callers can detect installed items that the tree does not place anywhere.
func placedInTree(forest []*cwhub.ItemNode) map[string]bool {
	placed := make(map[string]bool)

	var walk func(n *cwhub.ItemNode)
	walk = func(n *cwhub.ItemNode) {
		placed[n.Item.FQName()] = true
		for _, c := range n.Children {
			walk(c)
		}
	}

	for _, n := range forest {
		walk(n)
	}

	return placed
}

// flatRows turns a flat list of items into depth-0 rows for the search / -a views.
func flatRows(items []*cwhub.Item) []overviewRow {
	rows := make([]overviewRow, 0, len(items))
	for _, item := range items {
		rows = append(rows, overviewRow{item: item})
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

		appendItemRow(t, row.item, row.prefix, showDesc, colorize)

		if row.depth == 0 && row.item.Type == cwhub.COLLECTIONS {
			afterCollectionRoot = true
		}
	}

	fmt.Fprintln(out, t.Render())
}
