package main

import (
	"fmt"
	"io"
	"os"

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

func renderTableTitle(out io.Writer, title string) {
	if out == nil {
		panic("renderTableTitle: out is nil")
	}
	if title == "" {
		return
	}
	fmt.Fprintln(out, title)
}
