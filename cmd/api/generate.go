package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewGenerateCommand() *cobra.Command {
	var cmdGenerate = &cobra.Command{
		Use:   "generate",
		Short: "generate",
		Args:  cobra.ExactArgs(1),
	}

	var cmdGenerateKey = &cobra.Command{
		Use:   "key <name>",
		Short: "key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key, err := csAPI.Generate(args[0])
			if err != nil {
				log.Fatalf("unable to create api key: %s", err)
			}
			fmt.Printf("Api key for '%s':\n\n", args[0])
			fmt.Printf("   %s\n\n", key)
			fmt.Print("Please keep this key since will not be able to retrive it!\n")
		},
	}

	cmdGenerate.AddCommand(cmdGenerateKey)
	return cmdGenerate
}
