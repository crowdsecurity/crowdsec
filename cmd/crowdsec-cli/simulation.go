//go:build linux

package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

type cliSimulation struct {
	cfg configGetter
}

func NewCLISimulation(cfg configGetter) *cliSimulation {
	return &cliSimulation{
		cfg: cfg,
	}
}

var ErrSimulationDeprecated = errors.New("command 'simulation' has been removed, please read https://docs.crowdsec.net/blog/cscli_simulation_deprecation/")

func (cli *cliSimulation) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "simulation [command]",
		Hidden:            true,
		Short:             "Manage simulation status of scenarios",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return ErrSimulationDeprecated
		},
	}

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Println(ErrSimulationDeprecated.Error())
	})

	return cmd
}
