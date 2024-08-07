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
	var target string

	const defaultTarget = "./doc"

	cmd := &cobra.Command{
		Use:               "doc",
		Short:             "Generate the documentation related to cscli commands. Target directory must exist.",
		Args:              cobra.NoArgs,
		Hidden:            true,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if err := doc.GenMarkdownTreeCustom(rootCmd, target, cli.filePrepender, cli.linkHandler); err != nil {
				return fmt.Errorf("failed to generate cscli documentation: %w", err)
			}

			fmt.Println("Documentation generated in", target)

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&target, "target", defaultTarget, "The target directory where the documentation will be generated")

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
