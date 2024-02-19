package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

type cliDoc struct{}

func NewCLIDoc() *cliDoc {
	return &cliDoc{}
}

func (cli cliDoc) NewCommand(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "doc",
		Short:             "Generate the documentation in `./doc/`. Directory must exist.",
		Args:              cobra.ExactArgs(0),
		Hidden:            true,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := doc.GenMarkdownTreeCustom(rootCmd, "./doc/", cli.filePrepender, cli.linkHandler); err != nil {
				return fmt.Errorf("failed to generate cobra doc: %s", err)
			}
			return nil
		},
	}

	return cmd
}

func (cli cliDoc) filePrepender(filename string) string {
	const header = `---
id: %s
title: %s
---
`
	name := filepath.Base(filename)
	base := strings.TrimSuffix(name, filepath.Ext(name))
	return fmt.Sprintf(header, base, strings.ReplaceAll(base, "_", " "))
}

func (cli cliDoc) linkHandler(name string) string {
	return fmt.Sprintf("/cscli/%s", name)
}
