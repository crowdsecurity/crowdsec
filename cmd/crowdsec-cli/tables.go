package main

import (
	"fmt"
	"io"
	"os"

	isatty "github.com/mattn/go-isatty"
)

func shouldWeColorize() bool {
	switch csConfig.Cscli.Color {
	case "yes":
		return true
	case "no":
		return false
	default:
		return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	}
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
