package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"slices"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type cliSimulation struct{}

func NewCLISimulation() *cliSimulation {
	return &cliSimulation{}
}

func (cli cliSimulation) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "simulation [command]",
		Short: "Manage simulation status of scenarios",
		Example: `cscli simulation status
cscli simulation enable crowdsecurity/ssh-bf
cscli simulation disable crowdsecurity/ssh-bf`,
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadSimulation(); err != nil {
				log.Fatal(err)
			}
			if csConfig.Cscli.SimulationConfig == nil {
				return fmt.Errorf("no simulation configured")
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cmd.Name() != "status" {
				log.Infof(ReloadMessage())
			}
		},
	}
	cmd.Flags().SortFlags = false
	cmd.PersistentFlags().SortFlags = false

	cmd.AddCommand(cli.NewEnableCmd())
	cmd.AddCommand(cli.NewDisableCmd())
	cmd.AddCommand(cli.NewStatusCmd())

	return cmd
}

func (cli cliSimulation) NewEnableCmd() *cobra.Command {
	var forceGlobalSimulation bool

	cmd := &cobra.Command{
		Use:               "enable [scenario] [-global]",
		Short:             "Enable the simulation, globally or on specified scenarios",
		Example:           `cscli simulation enable`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			hub, err := require.Hub(csConfig, nil, nil)
			if err != nil {
				log.Fatal(err)
			}

			if len(args) > 0 {
				for _, scenario := range args {
					var item = hub.GetItem(cwhub.SCENARIOS, scenario)
					if item == nil {
						log.Errorf("'%s' doesn't exist or is not a scenario", scenario)
						continue
					}
					if !item.State.Installed {
						log.Warningf("'%s' isn't enabled", scenario)
					}
					isExcluded := slices.Contains(csConfig.Cscli.SimulationConfig.Exclusions, scenario)
					if *csConfig.Cscli.SimulationConfig.Simulation && !isExcluded {
						log.Warning("global simulation is already enabled")
						continue
					}
					if !*csConfig.Cscli.SimulationConfig.Simulation && isExcluded {
						log.Warningf("simulation for '%s' already enabled", scenario)
						continue
					}
					if *csConfig.Cscli.SimulationConfig.Simulation && isExcluded {
						if err := removeFromExclusion(scenario); err != nil {
							log.Fatal(err)
						}
						log.Printf("simulation enabled for '%s'", scenario)
						continue
					}
					if err := addToExclusion(scenario); err != nil {
						log.Fatal(err)
					}
					log.Printf("simulation mode for '%s' enabled", scenario)
				}
				if err := dumpSimulationFile(); err != nil {
					log.Fatalf("simulation enable: %s", err)
				}
			} else if forceGlobalSimulation {
				if err := enableGlobalSimulation(); err != nil {
					log.Fatalf("unable to enable global simulation mode : %s", err)
				}
			} else {
				printHelp(cmd)
			}
		},
	}
	cmd.Flags().BoolVarP(&forceGlobalSimulation, "global", "g", false, "Enable global simulation (reverse mode)")

	return cmd
}

func (cli cliSimulation) NewDisableCmd() *cobra.Command {
	var forceGlobalSimulation bool

	cmd := &cobra.Command{
		Use:               "disable [scenario]",
		Short:             "Disable the simulation mode. Disable only specified scenarios",
		Example:           `cscli simulation disable`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				for _, scenario := range args {
					isExcluded := slices.Contains(csConfig.Cscli.SimulationConfig.Exclusions, scenario)
					if !*csConfig.Cscli.SimulationConfig.Simulation && !isExcluded {
						log.Warningf("%s isn't in simulation mode", scenario)
						continue
					}
					if !*csConfig.Cscli.SimulationConfig.Simulation && isExcluded {
						if err := removeFromExclusion(scenario); err != nil {
							log.Fatal(err)
						}
						log.Printf("simulation mode for '%s' disabled", scenario)
						continue
					}
					if isExcluded {
						log.Warningf("simulation mode is enabled but is already disable for '%s'", scenario)
						continue
					}
					if err := addToExclusion(scenario); err != nil {
						log.Fatal(err)
					}
					log.Printf("simulation mode for '%s' disabled", scenario)
				}
				if err := dumpSimulationFile(); err != nil {
					log.Fatalf("simulation disable: %s", err)
				}
			} else if forceGlobalSimulation {
				if err := disableGlobalSimulation(); err != nil {
					log.Fatalf("unable to disable global simulation mode : %s", err)
				}
			} else {
				printHelp(cmd)
			}
		},
	}
	cmd.Flags().BoolVarP(&forceGlobalSimulation, "global", "g", false, "Disable global simulation (reverse mode)")

	return cmd
}

func (cli cliSimulation) NewStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Show simulation mode status",
		Example:           `cscli simulation status`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := simulationStatus(); err != nil {
				log.Fatal(err)
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
		},
	}

	return cmd
}

func addToExclusion(name string) error {
	csConfig.Cscli.SimulationConfig.Exclusions = append(csConfig.Cscli.SimulationConfig.Exclusions, name)
	return nil
}

func removeFromExclusion(name string) error {
	index := slices.Index(csConfig.Cscli.SimulationConfig.Exclusions, name)

	// Remove element from the slice
	csConfig.Cscli.SimulationConfig.Exclusions[index] = csConfig.Cscli.SimulationConfig.Exclusions[len(csConfig.Cscli.SimulationConfig.Exclusions)-1]
	csConfig.Cscli.SimulationConfig.Exclusions[len(csConfig.Cscli.SimulationConfig.Exclusions)-1] = ""
	csConfig.Cscli.SimulationConfig.Exclusions = csConfig.Cscli.SimulationConfig.Exclusions[:len(csConfig.Cscli.SimulationConfig.Exclusions)-1]

	return nil
}

func enableGlobalSimulation() error {
	csConfig.Cscli.SimulationConfig.Simulation = new(bool)
	*csConfig.Cscli.SimulationConfig.Simulation = true
	csConfig.Cscli.SimulationConfig.Exclusions = []string{}

	if err := dumpSimulationFile(); err != nil {
		log.Fatalf("unable to dump simulation file: %s", err)
	}

	log.Printf("global simulation: enabled")

	return nil
}

func dumpSimulationFile() error {
	newConfigSim, err := yaml.Marshal(csConfig.Cscli.SimulationConfig)
	if err != nil {
		return fmt.Errorf("unable to marshal simulation configuration: %s", err)
	}
	err = os.WriteFile(csConfig.ConfigPaths.SimulationFilePath, newConfigSim, 0o644)
	if err != nil {
		return fmt.Errorf("write simulation config in '%s' failed: %s", csConfig.ConfigPaths.SimulationFilePath, err)
	}
	log.Debugf("updated simulation file %s", csConfig.ConfigPaths.SimulationFilePath)

	return nil
}

func disableGlobalSimulation() error {
	csConfig.Cscli.SimulationConfig.Simulation = new(bool)
	*csConfig.Cscli.SimulationConfig.Simulation = false

	csConfig.Cscli.SimulationConfig.Exclusions = []string{}
	newConfigSim, err := yaml.Marshal(csConfig.Cscli.SimulationConfig)
	if err != nil {
		return fmt.Errorf("unable to marshal new simulation configuration: %s", err)
	}
	err = os.WriteFile(csConfig.ConfigPaths.SimulationFilePath, newConfigSim, 0o644)
	if err != nil {
		return fmt.Errorf("unable to write new simulation config in '%s' : %s", csConfig.ConfigPaths.SimulationFilePath, err)
	}

	log.Printf("global simulation: disabled")
	return nil
}

func simulationStatus() error {
	if csConfig.Cscli.SimulationConfig == nil {
		log.Printf("global simulation: disabled (configuration file is missing)")
		return nil
	}
	if *csConfig.Cscli.SimulationConfig.Simulation {
		log.Println("global simulation: enabled")
		if len(csConfig.Cscli.SimulationConfig.Exclusions) > 0 {
			log.Println("Scenarios not in simulation mode :")
			for _, scenario := range csConfig.Cscli.SimulationConfig.Exclusions {
				log.Printf("  - %s", scenario)
			}
		}
	} else {
		log.Println("global simulation: disabled")
		if len(csConfig.Cscli.SimulationConfig.Exclusions) > 0 {
			log.Println("Scenarios in simulation mode :")
			for _, scenario := range csConfig.Cscli.SimulationConfig.Exclusions {
				log.Printf("  - %s", scenario)
			}
		}
	}
	return nil
}
