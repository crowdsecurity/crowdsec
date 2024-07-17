package cstable

// transisional file to keep (minimal) backwards compatibility with the old table
// we can migrate the code to the new dependency later, it can already use the Writer interface

import (
	"fmt"
	"io"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	isatty "github.com/mattn/go-isatty"
)

func shouldWeColorize(wantColor string) bool {
	switch wantColor {
	case "yes":
		return true
	case "no":
		return false
	default:
		return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	}
}

type Table struct {
	Writer      table.Writer
	output      io.Writer
	align       []text.Align
	alignHeader []text.Align
}

func New(out io.Writer, wantColor string) *Table {
	if out == nil {
		panic("newTable: out is nil")
	}

	t := table.NewWriter()

	// colorize output, use unicode box characters
	fancy := shouldWeColorize(wantColor)

	colorOptions := table.ColorOptions{}

	if fancy {
		colorOptions.Header = text.Colors{text.Italic}
		colorOptions.Border = text.Colors{text.FgHiBlack}
		colorOptions.Separator = text.Colors{text.FgHiBlack}
	}

	// no upper/lower case transformations
	format := table.FormatOptions{}

	box := table.StyleBoxDefault
	if fancy {
		box = table.StyleBoxRounded
	}

	style := table.Style{
		Box:     box,
		Color:   colorOptions,
		Format:  format,
		HTML:    table.DefaultHTMLOptions,
		Options: table.OptionsDefault,
		Title:   table.TitleOptionsDefault,
	}

	t.SetStyle(style)

	return &Table{
		Writer:      t,
		output:      out,
		align:       make([]text.Align, 0),
		alignHeader: make([]text.Align, 0),
	}
}

func NewLight(output io.Writer, wantColor string) *Table {
	t := New(output, wantColor)
	s := t.Writer.Style()
	s.Box.Left = ""
	s.Box.LeftSeparator = ""
	s.Box.TopLeft = ""
	s.Box.BottomLeft = ""
	s.Box.Right = ""
	s.Box.RightSeparator = ""
	s.Box.TopRight = ""
	s.Box.BottomRight = ""
	s.Options.SeparateRows = false
	s.Options.SeparateFooter = false
	s.Options.SeparateHeader = true
	s.Options.SeparateColumns = false

	return t
}

//
// wrapper methods for backwards compatibility
//

// setColumnConfigs must be called right before rendering,
// to allow for setting the alignment like the old API
func (t *Table) setColumnConfigs() {
	configs := []table.ColumnConfig{}
	// the go-pretty table does not expose the names or number of columns
	for i := range len(t.align) {
		configs = append(configs, table.ColumnConfig{
			Number:           i + 1,
			AlignHeader:      t.alignHeader[i],
			Align:            t.align[i],
			WidthMax:         60,
			WidthMaxEnforcer: text.WrapSoft,
		})
	}

	t.Writer.SetColumnConfigs(configs)
}

func (t *Table) Render() {
	// change default options for backwards compatibility.
	// we do this late to allow changing the alignment like the old API
	t.setColumnConfigs()
	fmt.Fprintln(t.output, t.Writer.Render())
}

func (t *Table) SetHeaders(str ...string) {
	row := table.Row{}
	t.align = make([]text.Align, len(str))
	t.alignHeader = make([]text.Align, len(str))

	for i, v := range str {
		row = append(row, v)
		t.align[i] = text.AlignLeft
		t.alignHeader[i] = text.AlignCenter
	}

	t.Writer.AppendHeader(row)
}

func (t *Table) AddRow(str ...string) {
	row := table.Row{}
	for _, v := range str {
		row = append(row, v)
	}

	t.Writer.AppendRow(row)
}

func (t *Table) SetRowLines(rowLines bool) {
	t.Writer.Style().Options.SeparateRows = rowLines
}

func (t *Table) SetAlignment(align ...text.Align) {
	// align can be shorter than t.align, it will leave the default value
	copy(t.align, align)
}

func (t *Table) SetHeaderAlignment(align ...text.Align) {
	copy(t.alignHeader, align)
}
