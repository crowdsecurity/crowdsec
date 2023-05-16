package table

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	runewidth "github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

// Table holds information required to render a table to the terminal
type Table struct {
	w                   io.Writer
	data                [][]string
	formatted           []iRow
	headers             [][]string
	footers             [][]string
	alignments          []Alignment
	headerAlignments    []Alignment
	footerAlignments    []Alignment
	borders             Borders
	lineStyle           Style
	dividers            Dividers
	maxColumnWidth      int
	padding             int
	cursorStyle         Style
	rowLines            bool
	autoMerge           bool
	autoMergeHeaders    bool
	headerStyle         Style
	headerColspans      map[int][]int
	contentColspans     map[int][]int
	footerColspans      map[int][]int
	availableWidth      int
	headerVerticalAlign Alignment
	fillWidth           bool
}

type iRow struct {
	header bool
	footer bool
	cols   []iCol
	first  bool
	last   bool
	height int
}

type iCol struct {
	original   string
	span       int
	lines      []ansiBlob
	width      int
	first      bool
	last       bool
	height     int
	mergeAbove bool
	mergeBelow bool
	alignment  Alignment
}

func (c iCol) MaxWidth() int {
	var maxWidth int
	for _, line := range c.lines {
		if line.Len() > maxWidth {
			maxWidth = line.Len()
		}
	}
	return maxWidth
}

// Borders dictates whether to draw lines at the extreme edges of the table
type Borders struct {
	Left   bool
	Top    bool
	Right  bool
	Bottom bool
}

// New creates a new Table
func New(w io.Writer) *Table {

	availableWidth := 80
	if w == os.Stdout {
		width, _, _ := term.GetSize(int(os.Stdout.Fd()))
		if width > 0 {
			availableWidth = width
		}
	}

	return &Table{
		w:                w,
		data:             nil,
		headers:          nil,
		footers:          nil,
		alignments:       nil,
		headerAlignments: nil,
		footerAlignments: nil,
		borders: Borders{
			Left:   true,
			Top:    true,
			Right:  true,
			Bottom: true,
		},
		lineStyle:           StyleNormal,
		dividers:            UnicodeDividers,
		maxColumnWidth:      60,
		padding:             1,
		rowLines:            true,
		autoMerge:           false,
		headerColspans:      make(map[int][]int),
		contentColspans:     make(map[int][]int),
		footerColspans:      make(map[int][]int),
		availableWidth:      availableWidth,
		headerVerticalAlign: AlignTop,
	}
}

// SetBorders enables/disables the border around the table
func (t *Table) SetBorders(enabled bool) {
	t.borders = Borders{
		Left:   enabled,
		Top:    enabled,
		Right:  enabled,
		Bottom: enabled,
	}
}

// SetBorderLeft enables/disables the border line on the left edge of the table
func (t *Table) SetBorderLeft(enabled bool) {
	t.borders.Left = enabled
}

// SetBorderRight enables/disables the border line on the right edge of the table
func (t *Table) SetBorderRight(enabled bool) {
	t.borders.Right = enabled
}

// SetBorderTop enables/disables the border line on the top edge of the table
func (t *Table) SetBorderTop(enabled bool) {
	t.borders.Top = enabled
}

// SetBorderBottom enables/disables the border line on the bottom edge of the table
func (t *Table) SetBorderBottom(enabled bool) {
	t.borders.Bottom = enabled
}

// SetLineStyle sets the ANSI style of the lines used when drawing the table. e.g. StyleYellow
func (t *Table) SetLineStyle(s Style) {
	t.lineStyle = s
}

// SetRowLines sets whether to render horizontal lines between rows
func (t *Table) SetRowLines(enabled bool) {
	t.rowLines = enabled
}

// SetAutoMerge sets whether to merge cells vertically if their content is the same and non-empty
func (t *Table) SetAutoMerge(enabled bool) {
	t.autoMerge = enabled
}

// SetFillWidth sets whether to fill the entire available width
func (t *Table) SetFillWidth(enabled bool) {
	t.fillWidth = enabled
}

// SetAutoMergeHeaders sets whether to merge header cells vertically if their content is the same and non-empty
func (t *Table) SetAutoMergeHeaders(enabled bool) {
	t.autoMergeHeaders = enabled
}

// SetAlignment sets the alignment of each column. Should be specified for each column in the supplied data.
// Default alignment for columns is AlignLeft
func (t *Table) SetAlignment(columns ...Alignment) {
	t.alignments = columns
}

// SetHeaderAlignment sets the alignment of each header. Should be specified for each header in the supplied data.
// Default alignment for headers is AlignCenter
func (t *Table) SetHeaderAlignment(columns ...Alignment) {
	t.headerAlignments = columns
}

func (t *Table) SetHeaderVerticalAlignment(a Alignment) {
	t.headerVerticalAlign = a
}

// SetFooterAlignment sets the alignment of each footer. Should be specified for each footer in the supplied data.
// Default alignment for footers is AlignCenter
func (t *Table) SetFooterAlignment(columns ...Alignment) {
	t.footerAlignments = columns
}

// SetHeaders set the headers used for the table.
func (t *Table) SetHeaders(headers ...string) {
	t.headers = [][]string{headers}
}

// AddHeaders adds a row of headers to the table.
func (t *Table) AddHeaders(headers ...string) {
	t.headers = append(t.headers, headers)
}

// SetHeaderStyle set the style used for headers
func (t *Table) SetHeaderStyle(s Style) {
	t.headerStyle = s
}

// SetFooters set the footers used for the table.
func (t *Table) SetFooters(footers ...string) {
	t.footers = [][]string{footers}
}

// AddFooters adds a row of footers to the table.
func (t *Table) AddFooters(footers ...string) {
	t.footers = append(t.footers, footers)
}

// SetPadding sets the minimum number of spaces which must surround each column value (horizontally).
// For example, a padding of 3 would result in a column value such as "   hello world   " (3 spaces either side)
func (t *Table) SetPadding(padding int) {
	t.padding = padding
}

// SetDividers allows customisation of the characters used to draw the table.
// There are several built-in options, such as UnicodeRoundedDividers.
// Specifying divider values containing more than 1 rune will result in undefined behaviour.
func (t *Table) SetDividers(d Dividers) {
	t.dividers = d
}

// AddRow adds a row to the table. Each argument is a column value.
func (t *Table) AddRow(cols ...string) {
	t.data = append(t.data, cols)
}

// SetAvailableWidth sets the available width for the table (defaults to terminal width when stdout is used)
func (t *Table) SetAvailableWidth(w int) {
	t.availableWidth = w
}

// AddRows adds multiple rows to the table. Each argument is a row, i.e. a slice of column values.
func (t *Table) AddRows(rows ...[]string) {
	t.data = append(t.data, rows...)
}

// SetColumnMaxWidth sets the max column width
func (t *Table) SetColumnMaxWidth(maxColumnWidth int) {
	t.maxColumnWidth = maxColumnWidth
}

// LoadCSV loads CSV data from a reader and adds it to the table. Existing rows/headers/footers are retained.
func (t *Table) LoadCSV(r io.Reader, hasHeaders bool) error {
	cr := csv.NewReader(r)

	if hasHeaders {
		headers, err := cr.Read()
		if err != nil {
			return err
		}
		t.SetHeaders(headers...)
	}

	for {
		data, err := cr.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		t.AddRow(data...)
	}

	return nil
}

func (t *Table) getAlignment(colIndex int, header bool, footer bool) Alignment {
	switch {
	case header:
		if colIndex >= len(t.headerAlignments) {
			return AlignCenter
		}
		return t.headerAlignments[colIndex]
	case footer:
		if colIndex >= len(t.footerAlignments) {
			return AlignCenter
		}
		return t.footerAlignments[colIndex]
	default:
		if colIndex >= len(t.alignments) {
			return AlignLeft
		}
		return t.alignments[colIndex]
	}
}

// find the most columns we have in any given row, header, or footer
func (t *Table) findMaxCols() int {
	var maxCols int
	for i, r := range t.headers {
		rowTotal := 0
		for c := range r {
			rowTotal += t.getColspan(true, false, i, c)
		}
		if rowTotal > maxCols {
			maxCols = rowTotal
		}
	}
	for i, r := range t.data {
		rowTotal := 0
		for c := range r {
			rowTotal += t.getColspan(false, false, i, c)
		}
		if rowTotal > maxCols {
			maxCols = rowTotal
		}
	}
	for i, r := range t.footers {
		rowTotal := 0
		for c := range r {
			rowTotal += t.getColspan(false, true, i, c)
		}
		if rowTotal > maxCols {
			maxCols = rowTotal
		}
	}
	return maxCols
}

func (t *Table) formatData() {

	var formatted []iRow

	maxCols := t.findMaxCols()

	// add headers
	if len(t.headers) > 0 {
		for i, headerSet := range t.headers {
			headerRow := iRow{
				header: true,
				footer: false,
				cols:   nil,
				first:  i == 0,
				last:   i == len(t.headers)-1 && len(t.data)+len(t.footers) == 0,
			}
			for j, heading := range headerSet {
				headerRow.cols = append(headerRow.cols, iCol{
					original:  heading,
					width:     runewidth.StringWidth(heading),
					first:     j == 0,
					last:      j == maxCols-1,
					alignment: t.getAlignment(j, true, false),
					span:      t.getColspan(true, false, i, j),
				})
			}
			formatted = append(formatted, headerRow)
		}
	}

	// add rows
	for rowIndex, cols := range t.data {
		fRow := iRow{
			header: false,
			footer: false,
			cols:   nil,
			first:  rowIndex == 0 && len(formatted) == 0,
			last:   rowIndex == len(t.data)-1 && len(t.footers) == 0,
		}
		for colIndex, data := range cols {
			fRow.cols = append(fRow.cols, iCol{
				original:  data,
				width:     runewidth.StringWidth(data),
				first:     colIndex == 0,
				last:      colIndex == maxCols-1,
				alignment: t.getAlignment(colIndex, false, false),
				span:      t.getColspan(false, false, rowIndex, colIndex),
			})
		}
		formatted = append(formatted, fRow)
	}

	// add footers
	if len(t.footers) > 0 {
		for i, footerSet := range t.footers {
			footerRow := iRow{
				header: false,
				footer: true,
				cols:   nil,
				first:  len(formatted) == 0,
				last:   i == len(t.footers)-1,
			}
			for j, footing := range footerSet {
				footerRow.cols = append(footerRow.cols, iCol{
					original:  footing,
					width:     runewidth.StringWidth(footing),
					first:     j == 0,
					last:      j == maxCols-1,
					alignment: t.getAlignment(j, false, true),
					span:      t.getColspan(false, true, i, j),
				})
			}
			formatted = append(formatted, footerRow)
		}
	}

	formatted = t.equaliseRows(formatted, maxCols)
	formatted = t.formatContent(formatted)
	t.formatted = t.mergeContent(formatted)
}

func (t *Table) calcColumnWidth(rowIndex int, row iRow) int {
	rowTotal := 0
	for c := range row.cols {
		rowTotal += t.getColspan(row.header, row.footer, rowIndex, c)
	}
	return rowTotal
}

func (t *Table) equaliseRows(formatted []iRow, maxCols int) []iRow {
	// ensure all rows have the same number of columns (taking colspan into account)
	for i, row := range formatted {
		if len(row.cols) > 0 {
			row.cols[len(row.cols)-1].last = false
		}
		for t.calcColumnWidth(i, row) < maxCols {
			row.cols = append(row.cols, iCol{
				first: len(row.cols) == 0,
				span:  1,
			})
		}
		if len(row.cols) > 0 {
			row.cols[len(row.cols)-1].last = true
		}
		formatted[i] = row
	}
	return formatted
}

func (t *Table) formatContent(formatted []iRow) []iRow {

	var maxWidth int
	for _, row := range formatted {
		rowWidth := 1
		for _, col := range row.cols {
			rowWidth += col.width + (t.padding * 2) + 1
		}
		if rowWidth > maxWidth {
			maxWidth = rowWidth
		}
	}
	enableWrapping := t.availableWidth < maxWidth

	// wrap text
	for r, row := range formatted {
		maxLines := 0
		for c, col := range row.cols {
			wrapLen := t.maxColumnWidth
			if !enableWrapping {
				wrapLen = runewidth.StringWidth(col.original)
			}
			wrapped := wrapText(col.original, wrapLen)
			formatted[r].cols[c].lines = wrapped
			if len(wrapped) > maxLines {
				maxLines = len(wrapped)
			}
		}
		// ensure all cols have the same number of lines for a given row
		for c, col := range row.cols {
			col.lines = t.alignVertically(col.lines, AlignTop, maxLines)
			col.height = len(col.lines)
			formatted[r].cols[c] = col
		}
		// set height for row
		formatted[r].height = maxLines
	}

	spares := make([]int, len(formatted))
	for r, row := range formatted {
		spare := t.availableWidth - 1
		for c, col := range row.cols {
			spare -= col.MaxWidth() + (t.getColspan(row.header, row.footer, r, c) * ((t.padding * 2) + 1))
		}
		if spare < 0 {
			spare = 0
		}
		spares[r] = spare
	}

	var extra int

	// set width of each col, and align text
	for c := 0; c < t.calcColumnWidth(0, formatted[0]); c++ { // for each col

		// find max width for column across all rows
		maxWidth := 0
		for r, row := range formatted {

			if c >= len(row.cols) || row.cols[c].span > 1 {
				// ignore columns with a colspan > 1 for now, we'll apply those next
				continue
			}

			if t.fillWidth {
				extra = spares[r] / len(row.cols)
			}
			width := row.cols[c].MaxWidth() + extra
			if width > maxWidth {
				maxWidth = width
			}

		}

		// set uniform col width, and align all content
		for r, row := range formatted {
			if c >= len(row.cols) {
				continue
			}
			row.cols[c].width = maxWidth
			for l, line := range row.cols[c].lines {
				row.cols[c].lines[l] = align(line, maxWidth, row.cols[c].alignment)
			}
			formatted[r] = row
		}
	}

	return t.applyColSpans(formatted)
}

func (t *Table) alignVertically(lines []ansiBlob, alignment Alignment, maxLines int) []ansiBlob {
	switch alignment {
	case AlignBottom:
		for len(lines) < maxLines {
			lines = append([]ansiBlob{newANSI("")}, lines...)
		}
	default:
		for len(lines) < maxLines {
			lines = append(lines, newANSI(""))
		}
	}
	return lines
}

// e.g. 5 rows, 2nd with span 5, input 7 returns 3rd row
func (t *Table) getRealIndex(row iRow, index int) int {
	var relative int
	for actual, col := range row.cols {
		if relative == index {
			return actual
		}
		relative += col.span
	}
	return len(row.cols)
}

func (t *Table) getRelativeIndex(row iRow, index int) int {
	var relative int
	for actual := 0; actual < len(row.cols) && actual < index; actual++ {
		relative += row.cols[actual].span
	}
	return relative
}

func (t *Table) applyColSpans(formatted []iRow) []iRow {
	type colSpanJob struct {
		row         int
		relativeCol int
		span        int
	}
	var jobs []colSpanJob
	for i, row := range formatted {
		for j, col := range row.cols {
			if col.span > 1 {
				jobs = append(jobs, colSpanJob{
					row:         i,
					relativeCol: t.getRelativeIndex(row, j),
					span:        col.span,
				})
			}
		}
	}
	for _, job := range jobs {

		realTargetColIndex := t.getRealIndex(formatted[job.row], job.relativeCol)

		// grab the cell that has a col span applied
		target := formatted[job.row].cols[realTargetColIndex]

		// calculate the width required for this cell
		targetWidth := target.MaxWidth()

		// calculate width required to render the cells beneath/above this cell - plus padding/dividers between them
		var childrenWidth int
		for i, row := range formatted {
			if i == job.row { // skip the row we're working on
				continue
			}
			var rowWidth int
			start := t.getRealIndex(row, job.relativeCol)
			stop := t.getRealIndex(row, job.relativeCol+job.span)
			for j := start; j < stop; j++ {
				rowWidth += row.cols[j].width
			}
			if rowWidth > childrenWidth {
				childrenWidth = rowWidth
			}
		}
		childrenWidth += (job.span - 1) * (1 + (2 * t.padding))

		switch {
		case childrenWidth == targetWidth:
			// everything is somehow magically fine
			target.width = childrenWidth
			formatted[job.row].cols[realTargetColIndex] = target
		case childrenWidth > targetWidth:
			// we need to grow our target cell to make it aligned with the children
			for i := range target.lines {
				target.lines[i] = align(target.lines[i], childrenWidth, target.alignment)
			}
			target.width = childrenWidth
			formatted[job.row].cols[realTargetColIndex] = target
		default:
			// we need to extend the children to align with the wide cell
			// we can do this by sharing the extra space between them
			available := targetWidth - childrenWidth
			share := available / job.span
			remainder := available - (share * (job.span - 1))

			// allocate each child some room
			for i, row := range formatted {
				if i == job.row { // skip the row we're working on
					continue
				}
				start := t.getRealIndex(row, job.relativeCol)
				stop := t.getRealIndex(row, job.relativeCol+job.span)
				for j := start; j < stop; j++ {
					amount := share
					if j == stop-1 {
						amount = remainder
					}
					row.cols[j].width += amount
					for k, line := range row.cols[j].lines {
						row.cols[j].lines[k] = align(line, row.cols[j].width, row.cols[j].alignment)
					}
				}
				formatted[i] = row
			}
			target.width = targetWidth
			formatted[job.row].cols[realTargetColIndex] = target
		}
	}

	var lastColMaxWidth int
	for r, row := range formatted {
		col := row.cols[len(row.cols)-1]
		if t.getColspan(row.header, row.footer, r, len(row.cols)-1) > 1 {
			continue
		}
		width := col.width
		if width > lastColMaxWidth {
			lastColMaxWidth = width
		}
	}
	for r, row := range formatted {
		c := len(row.cols) - 1
		if t.getColspan(row.header, row.footer, r, c) > 1 {
			continue
		}
		width := row.cols[c].width
		if width < lastColMaxWidth {
			row.cols[c].width = lastColMaxWidth
			for k, line := range row.cols[c].lines {
				row.cols[c].lines[k] = align(line, lastColMaxWidth, row.cols[c].alignment)
			}
			formatted[r] = row
		}
	}

	return formatted
}

func (t *Table) mergeContent(formatted []iRow) []iRow {

	columnCount := t.calcColumnWidth(0, formatted[0])
	lastValues := make([]string, columnCount)
	lastIndexes := make([]int, columnCount)

	// flag cols as mergeAbove where content matches and is non-empty
	for c := 0; c < columnCount; c++ {
		var prevHeader bool
		var allowed bool
		for r, row := range formatted {
			// don't merge columns with colspan > 1
			if t.getColspan(row.header, row.footer, r, c) > 1 {
				continue
			}
			if c >= len(row.cols) {
				continue
			}
			relativeIndex := t.getRelativeIndex(row, c)
			allowed = (row.header && t.autoMergeHeaders) || (!row.header && !row.footer && !prevHeader && t.autoMerge)
			prevHeader = row.header
			current := row.cols[c].original
			merge := current == lastValues[relativeIndex] && strings.TrimSpace(current) != ""
			row.cols[c].mergeAbove = merge && allowed
			if merge && allowed {
				lastIndex := lastIndexes[relativeIndex]
				formatted[r-1].cols[lastIndex].mergeBelow = true
				if t.headerVerticalAlign == AlignBottom {
					buffer := row.cols[c].lines
					row.cols[c].lines = formatted[r-1].cols[lastIndex].lines
					formatted[r-1].cols[lastIndex].lines = buffer
				}
			}
			lastValues[relativeIndex] = current
			lastIndexes[relativeIndex] = c
			formatted[r] = row
		}
	}

	return formatted
}

func (t *Table) renderRows() {
	var lastRow iRow
	for _, row := range t.formatted {
		t.renderRow(row, lastRow)
		lastRow = row
	}
}

func (t *Table) renderRow(row iRow, prev iRow) {
	t.renderLineAbove(row, prev)
	for y := 0; y < row.height; y++ {
		if t.borders.Left {
			t.setStyle(t.lineStyle)
			t.print(t.dividers.NS)
			t.resetStyle()
		}
		for _, col := range row.cols {
			if t.padding > 0 {
				t.print(strings.Repeat(" ", t.padding))
			}
			if col.mergeAbove && t.headerVerticalAlign == AlignTop {
				t.print(strings.Repeat(" ", col.width))
			} else if col.mergeBelow && t.headerVerticalAlign == AlignBottom {
				t.print(strings.Repeat(" ", col.width))
			} else {
				if row.header {
					t.setStyle(t.headerStyle)
				}
				t.print(col.lines[y].String())
				if row.header {
					t.resetStyle()
				}
			}
			if t.padding > 0 {
				t.print(strings.Repeat(" ", t.padding))
			}
			if t.borders.Right || !col.last {
				t.setStyle(t.lineStyle)
				t.print(t.dividers.NS)
				t.resetStyle()
			}
		}
		t.print("\n")
	}

	t.renderLineBelow(row)
}

// SetHeaderColSpans sets a column span for each column in the given header row.
func (t *Table) SetHeaderColSpans(rowIndex int, colSpans ...int) {
	t.headerColspans[rowIndex] = colSpans
}

// SetColSpans sets a column span for each column in the given row.
func (t *Table) SetColSpans(rowIndex int, colSpans ...int) {
	t.contentColspans[rowIndex] = colSpans
}

// SetFooterColSpans sets a column span for each column in the given footer row.
func (t *Table) SetFooterColSpans(rowIndex int, colSpans ...int) {
	t.footerColspans[rowIndex] = colSpans
}

func (t *Table) getColspan(header bool, footer bool, row int, col int) int {
	var target map[int][]int
	switch {
	case header:
		target = t.headerColspans
	case footer:
		target = t.footerColspans
	default:
		target = t.contentColspans
	}
	r, ok := target[row]
	if !ok {
		return 1
	}
	if col >= len(r) {
		return 1
	}
	c := r[col]
	if c < 1 {
		return 1
	}
	return c
}

// renders the line above a row
func (t *Table) renderLineAbove(row iRow, prev iRow) {

	// don't draw top border if disabled
	if (row.first && !t.borders.Top) || (!prev.header && !t.rowLines && !row.first) {
		return
	}

	t.setStyle(t.lineStyle)
	for i, col := range row.cols {

		prevIsMerged := i > 0 && row.cols[i-1].mergeAbove

		relativeIndex := t.getRelativeIndex(row, i)

		var aboveIsSpanned bool
		for j, prevCol := range prev.cols {
			prevRel := t.getRelativeIndex(prev, j)
			if prevRel >= relativeIndex {
				break
			}
			if prevRel+prevCol.span > relativeIndex {
				aboveIsSpanned = true
				break
			}
		}

		switch {
		case col.first && !t.borders.Left:
			// hide border
		case row.first && col.first:
			t.print(t.dividers.ES)
		case row.first:
			t.print(t.dividers.ESW)
		case col.first && col.mergeAbove:
			t.print(t.dividers.NS)
		case col.first:
			t.print(t.dividers.NES)
		case col.mergeAbove && prevIsMerged:
			t.print(t.dividers.NS)
		case col.mergeAbove && !aboveIsSpanned:
			t.print(t.dividers.NSW)
		case col.mergeAbove:
			t.print(t.dividers.SW)
		case prevIsMerged && !aboveIsSpanned:
			t.print(t.dividers.NES)
		case prevIsMerged:
			t.print(t.dividers.ES)
		case aboveIsSpanned:
			t.print(t.dividers.ESW)
		default:
			t.print(t.dividers.ALL)
		}
		if col.mergeAbove {
			t.print(strings.Repeat(" ", col.width+(t.padding*2)))
		} else {
			t.print(strings.Repeat(t.dividers.EW, col.width+(t.padding*2)))
		}
		switch {
		case col.last && !t.borders.Right:
			// hide border
		case col.last && row.first:
			t.print(t.dividers.SW)
		case col.last && col.mergeAbove:
			t.print(t.dividers.NS)
		case col.last:
			t.print(t.dividers.NSW)
		}
	}
	t.resetStyle()
	t.print("\n")
}

// renders the line below a row, if required
func (t *Table) renderLineBelow(row iRow) {
	// we only draw lines below the last row (if borders are on)
	if !row.last || !t.borders.Bottom {
		return
	}

	t.setStyle(t.lineStyle)
	for _, col := range row.cols {
		switch {
		case col.first && !t.borders.Left:
			// hide
		case col.first:
			t.print(t.dividers.NE)
		default:
			t.print(t.dividers.NEW)
		}
		t.print(strings.Repeat(t.dividers.EW, col.width+(t.padding*2)))
		if col.last && t.borders.Right {
			t.print(t.dividers.NW)
		}
	}
	t.resetStyle()
	t.print("\n")
}

func (t *Table) print(data string) {
	_, _ = fmt.Fprint(t.w, data)
}

func (t *Table) resetStyle() {
	t.setStyle(StyleNormal)
}

func (t *Table) setStyle(s Style) {
	if s != t.cursorStyle {
		_, _ = fmt.Fprintf(t.w, "\x1b[%dm", s)
	}
	t.cursorStyle = s
}

// Render writes the table to the provider io.Writer
func (t *Table) Render() {
	if len(t.headers) == 0 && len(t.footers) == 0 && len(t.data) == 0 {
		return
	}
	t.formatData()
	t.renderRows()
}
