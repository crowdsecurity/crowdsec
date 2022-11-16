package main

import (
	"fmt"
	"io"
	"os"

	"github.com/aquasecurity/table"
	isatty "github.com/mattn/go-isatty"
)

func shouldWeColorize() bool {
	if csConfig.Cscli.Color == "yes" {
		return true
	}
	if csConfig.Cscli.Color == "no" {
		return false
	}
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

func newTable(out io.Writer) *table.Table {
	if out == nil {
		panic("newTable: out is nil")
	}
	t := table.New(out)
	if shouldWeColorize() {
		t.SetLineStyle(table.StyleBrightBlack)
		t.SetHeaderStyle(table.StyleItalic)
	}

	if shouldWeColorize() {
		t.SetDividers(table.UnicodeRoundedDividers)
	} else {
		t.SetDividers(table.ASCIIDividers)
	}

	return t
}

func newLightTable(out io.Writer) *table.Table {
	if out == nil {
		panic("newTable: out is nil")
	}
	t := newTable(out)
	t.SetRowLines(false)
	t.SetBorderLeft(false)
	t.SetBorderRight(false)
	// This leaves three spaces between columns:
	// left padding, invisible border, right padding
	// There is no way to make two spaces without
	// a SetColumnLines() method, but it's close enough.
	t.SetPadding(1)

	if shouldWeColorize() {
		t.SetDividers(table.Dividers{
			ALL: "─",
			NES: "─",
			NSW: "─",
			NEW: "─",
			ESW: "─",
			NE:  "─",
			NW:  "─",
			SW:  "─",
			ES:  "─",
			EW:  "─",
			NS:  " ",
		})
	} else {
		t.SetDividers(table.Dividers{
			ALL: "-",
			NES: "-",
			NSW: "-",
			NEW: "-",
			ESW: "-",
			NE:  "-",
			NW:  "-",
			SW:  "-",
			ES:  "-",
			EW:  "-",
			NS:  " ",
		})
	}
	return t
}

func renderTableTitle(out io.Writer, title string) {
	if out == nil {
		panic("renderTableTitle: out is nil")
	}
	if title == "" {
		return
	}
	fmt.Fprintln(out, title)
}
