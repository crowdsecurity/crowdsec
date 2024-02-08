package main

import (
	"errors"
	"os"

	"github.com/fatih/color"
	cc "github.com/ivanpirog/coloredcobra"
	"github.com/spf13/cobra"
)

var (
	ErrorNoAPIKey = errors.New("CTI_API_KEY is not set")
)

type Config struct {
	API struct {
		CTI struct {
			Key string `yaml:"key"`
		} `yaml:"cti"`
	} `yaml:"api"`
}

func main() {
	var configPath string

	cmd := &cobra.Command{
		Use: "cscti",
		Short: "cscti is a tool to query the CrowdSec CTI",
		ValidArgs: []string{"smoke-ip"},
		DisableAutoGenTag: true,
	}

	cc.Init(&cc.Config{
		RootCmd:       cmd,
		Headings:      cc.Yellow,
		Commands:      cc.Green + cc.Bold,
		CmdShortDescr: cc.Cyan,
		Example:       cc.Italic,
		ExecName:      cc.Bold,
		Aliases:       cc.Bold + cc.Italic,
		FlagsDataType: cc.White,
		Flags:         cc.Green,
		FlagsDescr:    cc.Cyan,
	})
	cmd.SetOut(color.Output)

	pflags := cmd.PersistentFlags()

	pflags.StringVarP(&configPath, "config", "c", "", "Path to the configuration file")

	cmd.AddCommand(NewCLISmokeIP().NewCommand())

	if err := cmd.Execute(); err != nil {
		color.Red(err.Error())
		os.Exit(1)
	}
}
