package main

import (
	"fmt"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func addToExclusion(name string) error {
	config.SimulationCfg.Exclusions = append(config.SimulationCfg.Exclusions, name)
	return nil
}

func removeFromExclusion(name string) error {
	index := indexOf(name, config.SimulationCfg.Exclusions)

	// Remove element from the slice
	config.SimulationCfg.Exclusions[index] = config.SimulationCfg.Exclusions[len(config.SimulationCfg.Exclusions)-1]
	config.SimulationCfg.Exclusions[len(config.SimulationCfg.Exclusions)-1] = ""
	config.SimulationCfg.Exclusions = config.SimulationCfg.Exclusions[:len(config.SimulationCfg.Exclusions)-1]

	return nil
}

func enableGlobalSimulation() error {
	config.SimulationCfg.Simulation = true
	config.SimulationCfg.Exclusions = []string{}

	if err := dumpSimulationFile(); err != nil {
		log.Fatalf("unable to dump simulation file: %s", err.Error())
	}

	log.Printf("Simulation mode enabled")

	return nil
}

func dumpSimulationFile() error {
	newConfigSim, err := yaml.Marshal(config.SimulationCfg)
	if err != nil {
		return fmt.Errorf("unable to marshal simulation configuration: %s", err)
	}
	err = ioutil.WriteFile(config.SimulationCfgPath, newConfigSim, 0644)
	if err != nil {
		return fmt.Errorf("write simulation config in '%s' : %s", config.SimulationCfgPath, err)
	}

	return nil
}

func disableGlobalSimulation() error {
	config.SimulationCfg.Simulation = false
	config.SimulationCfg.Exclusions = []string{}
	newConfigSim, err := yaml.Marshal(config.SimulationCfg)
	if err != nil {
		return fmt.Errorf("unable to marshal new simulation configuration: %s", err)
	}
	err = ioutil.WriteFile(config.SimulationCfgPath, newConfigSim, 0644)
	if err != nil {
		return fmt.Errorf("unable to write new simulation config in '%s' : %s", config.SimulationCfgPath, err)
	}

	log.Printf("Simulation mode disabled")
	return nil
}

func simulationStatus() error {
	if config.SimulationCfg.Simulation {
		log.Println("Simulation mode is enabled")
		if len(config.SimulationCfg.Exclusions) > 0 {
			log.Println("Current scenarios are not in simulation mode :")
			for _, scenario := range config.SimulationCfg.Exclusions {
				log.Printf("  - %s", scenario)
			}
		}
	} else {
		log.Println("Simulation mode is disabled")
		if len(config.SimulationCfg.Exclusions) > 0 {
			log.Println("Current scenarios in simulation mode :")
			for _, scenario := range config.SimulationCfg.Exclusions {
				log.Printf("  - %s", scenario)
			}
		}
	}
	return nil
}

func NewSimulationCmds() *cobra.Command {
	var cmdSimulation = &cobra.Command{
		Use:   "simulation  enable|disable [scenario_name]",
		Short: "",
		Long:  ``,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before using bans")
			}
			return nil
		},
	}
	cmdSimulation.Flags().SortFlags = false
	cmdSimulation.PersistentFlags().SortFlags = false

	var cmdSimulationEnable = &cobra.Command{
		Use:     "enable [scenario_name]",
		Short:   "Enable the simulation mode. Enable only specified scenarios",
		Long:    ``,
		Example: `cscli simulation enable`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				for _, scenario := range args {
					isExcluded := inSlice(scenario, config.SimulationCfg.Exclusions)
					if config.SimulationCfg.Simulation && !isExcluded {
						log.Printf("'%s' is already in simulation mode", scenario)
						continue
					}
					if !config.SimulationCfg.Simulation && isExcluded {
						log.Printf("'%s' is already in simulation mode", scenario)
						continue
					}
					if config.SimulationCfg.Simulation && isExcluded {
						if err := removeFromExclusion(scenario); err != nil {
							log.Fatalf(err.Error())
						}
						log.Printf("simulation mode for '%s' enabled", scenario)
						continue
					}
					if isExcluded {
						log.Printf("'%s' is already in simulation mode", scenario)
						continue
					}
					if err := addToExclusion(scenario); err != nil {
						log.Fatalf(err.Error())
					}
					log.Printf("simulation mode for '%s' enabled", scenario)
				}
				if err := dumpSimulationFile(); err != nil {
					log.Fatalf("simulation enable: %s", err.Error())
				}
			} else {
				if err := enableGlobalSimulation(); err != nil {
					log.Fatalf("unable to enable global simulation mode : %s", err.Error())
				}
			}
		},
	}
	cmdSimulation.AddCommand(cmdSimulationEnable)

	var cmdSimulationDisable = &cobra.Command{
		Use:     "disable [scenario_name]",
		Short:   "Disable the simulation mode. Disable only specified scenarios",
		Long:    ``,
		Example: `cscli simulation disable`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				for _, scenario := range args {
					isExcluded := inSlice(scenario, config.SimulationCfg.Exclusions)
					if !config.SimulationCfg.Simulation && !isExcluded {
						log.Printf("simulation mode for '%s' is already disabled", scenario)
						continue
					}
					if !config.SimulationCfg.Simulation && isExcluded {
						if err := removeFromExclusion(scenario); err != nil {
							log.Fatalf(err.Error())
						}
						log.Printf("simulation mode for '%s' disabled", scenario)
						continue
					}
					if isExcluded {
						log.Printf("simulation mode for '%s' already disabled", scenario)
						continue
					}
					if err := addToExclusion(scenario); err != nil {
						log.Fatalf(err.Error())
					}
					log.Printf("simulation mode for '%s' disabled", scenario)
				}
				if err := dumpSimulationFile(); err != nil {
					log.Fatalf("simulation disable: %s", err.Error())
				}
			} else {
				if err := disableGlobalSimulation(); err != nil {
					log.Fatalf("unable to disable global simulation mode : %s", err.Error())
				}
			}
		},
	}
	cmdSimulation.AddCommand(cmdSimulationDisable)

	var cmdSimulationStatus = &cobra.Command{
		Use:     "status",
		Short:   "Show simulation mode status",
		Long:    ``,
		Example: `cscli simulation status`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := simulationStatus(); err != nil {
				log.Fatalf(err.Error())
			}
		},
	}
	cmdSimulation.AddCommand(cmdSimulationStatus)

	return cmdSimulation
}
