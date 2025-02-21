package clisimulation

import (
	"errors"
	"fmt"
	"os"
	"slices"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type configGetter func() *csconfig.Config

type cliSimulation struct {
	cfg configGetter
}

func New(cfg configGetter) *cliSimulation {
	return &cliSimulation{
		cfg: cfg,
	}
}

func (cli *cliSimulation) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "simulation [command]",
		Short: "Manage simulation status of scenarios",
		Example: `cscli simulation status
cscli simulation enable crowdsecurity/ssh-bf
cscli simulation disable crowdsecurity/ssh-bf`,
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if err := cli.cfg().LoadSimulation(); err != nil {
				return err
			}
			if cli.cfg().Cscli.SimulationConfig == nil {
				return errors.New("no simulation configured")
			}

			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, _ []string) {
			if msg := reload.UserMessage(); msg != "" && cmd.Name() != "status" {
				log.Info(msg)
			}
		},
	}
	cmd.Flags().SortFlags = false
	cmd.PersistentFlags().SortFlags = false

	cmd.AddCommand(cli.newEnableCmd())
	cmd.AddCommand(cli.newDisableCmd())
	cmd.AddCommand(cli.newStatusCmd())

	return cmd
}

func (cli *cliSimulation) newEnableCmd() *cobra.Command {
	var forceGlobalSimulation bool

	cmd := &cobra.Command{
		Use:               "enable [scenario] [-global]",
		Short:             "Enable the simulation, globally or on specified scenarios",
		Example:           `cscli simulation enable`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			hub, err := require.Hub(cli.cfg(), nil)
			if err != nil {
				return err
			}

			if len(args) > 0 {
				for _, scenario := range args {
					item := hub.GetItem(cwhub.SCENARIOS, scenario)
					if item == nil {
						log.Errorf("'%s' doesn't exist or is not a scenario", scenario)
						continue
					}
					if !item.State.Installed {
						log.Warningf("'%s' isn't enabled", scenario)
					}
					isExcluded := slices.Contains(cli.cfg().Cscli.SimulationConfig.Exclusions, scenario)
					if *cli.cfg().Cscli.SimulationConfig.Simulation && !isExcluded {
						log.Warning("global simulation is already enabled")
						continue
					}
					if !*cli.cfg().Cscli.SimulationConfig.Simulation && isExcluded {
						log.Warningf("simulation for '%s' already enabled", scenario)
						continue
					}
					if *cli.cfg().Cscli.SimulationConfig.Simulation && isExcluded {
						cli.removeFromExclusion(scenario)
						log.Printf("simulation enabled for '%s'", scenario)
						continue
					}
					cli.addToExclusion(scenario)
					log.Printf("simulation mode for '%s' enabled", scenario)
				}
				if err := cli.dumpSimulationFile(); err != nil {
					return fmt.Errorf("simulation enable: %w", err)
				}
			} else if forceGlobalSimulation {
				if err := cli.enableGlobalSimulation(); err != nil {
					return fmt.Errorf("unable to enable global simulation mode: %w", err)
				}
			} else {
				_ = cmd.Help()
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&forceGlobalSimulation, "global", "g", false, "Enable global simulation (reverse mode)")

	return cmd
}

func (cli *cliSimulation) newDisableCmd() *cobra.Command {
	var forceGlobalSimulation bool

	cmd := &cobra.Command{
		Use:               "disable [scenario]",
		Short:             "Disable the simulation mode. Disable only specified scenarios",
		Example:           `cscli simulation disable`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				for _, scenario := range args {
					isExcluded := slices.Contains(cli.cfg().Cscli.SimulationConfig.Exclusions, scenario)
					if !*cli.cfg().Cscli.SimulationConfig.Simulation && !isExcluded {
						log.Warningf("%s isn't in simulation mode", scenario)
						continue
					}
					if !*cli.cfg().Cscli.SimulationConfig.Simulation && isExcluded {
						cli.removeFromExclusion(scenario)
						log.Printf("simulation mode for '%s' disabled", scenario)
						continue
					}
					if isExcluded {
						log.Warningf("simulation mode is enabled but is already disable for '%s'", scenario)
						continue
					}
					cli.addToExclusion(scenario)
					log.Printf("simulation mode for '%s' disabled", scenario)
				}
				if err := cli.dumpSimulationFile(); err != nil {
					return fmt.Errorf("simulation disable: %w", err)
				}
			} else if forceGlobalSimulation {
				if err := cli.disableGlobalSimulation(); err != nil {
					return fmt.Errorf("unable to disable global simulation mode: %w", err)
				}
			} else {
				_ = cmd.Help()
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&forceGlobalSimulation, "global", "g", false, "Disable global simulation (reverse mode)")

	return cmd
}

func (cli *cliSimulation) newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Show simulation mode status",
		Example:           `cscli simulation status`,
		DisableAutoGenTag: true,
		Run: func(_ *cobra.Command, _ []string) {
			cli.status()
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
		},
	}

	return cmd
}

func (cli *cliSimulation) addToExclusion(name string) {
	cfg := cli.cfg()
	cfg.Cscli.SimulationConfig.Exclusions = append(cfg.Cscli.SimulationConfig.Exclusions, name)
}

func (cli *cliSimulation) removeFromExclusion(name string) {
	cfg := cli.cfg()
	index := slices.Index(cfg.Cscli.SimulationConfig.Exclusions, name)

	// Remove element from the slice
	cfg.Cscli.SimulationConfig.Exclusions[index] = cfg.Cscli.SimulationConfig.Exclusions[len(cfg.Cscli.SimulationConfig.Exclusions)-1]
	cfg.Cscli.SimulationConfig.Exclusions[len(cfg.Cscli.SimulationConfig.Exclusions)-1] = ""
	cfg.Cscli.SimulationConfig.Exclusions = cfg.Cscli.SimulationConfig.Exclusions[:len(cfg.Cscli.SimulationConfig.Exclusions)-1]
}

func (cli *cliSimulation) enableGlobalSimulation() error {
	cfg := cli.cfg()
	cfg.Cscli.SimulationConfig.Simulation = new(bool)
	*cfg.Cscli.SimulationConfig.Simulation = true
	cfg.Cscli.SimulationConfig.Exclusions = []string{}

	if err := cli.dumpSimulationFile(); err != nil {
		return fmt.Errorf("unable to dump simulation file: %w", err)
	}

	log.Printf("global simulation: enabled")

	return nil
}

func (cli *cliSimulation) dumpSimulationFile() error {
	cfg := cli.cfg()

	newConfigSim, err := yaml.Marshal(cfg.Cscli.SimulationConfig)
	if err != nil {
		return fmt.Errorf("unable to serialize simulation configuration: %w", err)
	}

	err = os.WriteFile(cfg.ConfigPaths.SimulationFilePath, newConfigSim, 0o644)
	if err != nil {
		return fmt.Errorf("write simulation config in '%s' failed: %w", cfg.ConfigPaths.SimulationFilePath, err)
	}

	log.Debugf("updated simulation file %s", cfg.ConfigPaths.SimulationFilePath)

	return nil
}

func (cli *cliSimulation) disableGlobalSimulation() error {
	cfg := cli.cfg()
	cfg.Cscli.SimulationConfig.Simulation = new(bool)
	*cfg.Cscli.SimulationConfig.Simulation = false

	cfg.Cscli.SimulationConfig.Exclusions = []string{}

	newConfigSim, err := yaml.Marshal(cfg.Cscli.SimulationConfig)
	if err != nil {
		return fmt.Errorf("unable to serialize new simulation configuration: %w", err)
	}

	err = os.WriteFile(cfg.ConfigPaths.SimulationFilePath, newConfigSim, 0o644)
	if err != nil {
		return fmt.Errorf("unable to write new simulation config in '%s': %w", cfg.ConfigPaths.SimulationFilePath, err)
	}

	log.Printf("global simulation: disabled")

	return nil
}

func (cli *cliSimulation) status() {
	cfg := cli.cfg()
	if cfg.Cscli.SimulationConfig == nil {
		log.Printf("global simulation: disabled (configuration file is missing)")
		return
	}

	if *cfg.Cscli.SimulationConfig.Simulation {
		log.Println("global simulation: enabled")

		if len(cfg.Cscli.SimulationConfig.Exclusions) > 0 {
			log.Println("Scenarios not in simulation mode :")

			for _, scenario := range cfg.Cscli.SimulationConfig.Exclusions {
				log.Printf("  - %s", scenario)
			}
		}
	} else {
		log.Println("global simulation: disabled")

		if len(cfg.Cscli.SimulationConfig.Exclusions) > 0 {
			log.Println("Scenarios in simulation mode :")

			for _, scenario := range cfg.Cscli.SimulationConfig.Exclusions {
				log.Printf("  - %s", scenario)
			}
		}
	}
}
