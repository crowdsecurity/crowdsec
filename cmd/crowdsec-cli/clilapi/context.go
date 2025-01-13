package clilapi

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

func (cli *cliLapi) addContext(key string, values []string) error {
	cfg := cli.cfg()

	if err := alertcontext.ValidateContextExpr(key, values); err != nil {
		return fmt.Errorf("invalid context configuration: %w", err)
	}

	if _, ok := cfg.Crowdsec.ContextToSend[key]; !ok {
		cfg.Crowdsec.ContextToSend[key] = make([]string, 0)

		log.Infof("key '%s' added", key)
	}

	data := cfg.Crowdsec.ContextToSend[key]

	for _, val := range values {
		if !slices.Contains(data, val) {
			log.Infof("value '%s' added to key '%s'", val, key)
			data = append(data, val)
		}

		cfg.Crowdsec.ContextToSend[key] = data
	}

	return cfg.Crowdsec.DumpContextConfigFile()
}

func (cli *cliLapi) newContextAddCmd() *cobra.Command {
	var (
		keyToAdd    string
		valuesToAdd []string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add context to send with alerts. You must specify the output key with the expr value you want",
		Example: `cscli lapi context add --key source_ip --value evt.Meta.source_ip
cscli lapi context add --key file_source --value evt.Line.Src
cscli lapi context add --value evt.Meta.source_ip --value evt.Meta.target_user 
		`,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			hub, err := require.Hub(cli.cfg(), nil)
			if err != nil {
				return err
			}

			if err = alertcontext.LoadConsoleContext(cli.cfg(), hub); err != nil {
				return fmt.Errorf("while loading context: %w", err)
			}

			if keyToAdd != "" {
				return cli.addContext(keyToAdd, valuesToAdd)
			}

			for _, v := range valuesToAdd {
				keySlice := strings.Split(v, ".")
				key := keySlice[len(keySlice)-1]
				value := []string{v}
				if err := cli.addContext(key, value); err != nil {
					return err
				}
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&keyToAdd, "key", "k", "", "The key of the different values to send")
	flags.StringSliceVar(&valuesToAdd, "value", []string{}, "The expr fields to associate with the key")

	_ = cmd.MarkFlagRequired("value")

	return cmd
}

func (cli *cliLapi) newContextStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "List context to send with alerts",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			hub, err := require.Hub(cfg, nil)
			if err != nil {
				return err
			}

			if err = alertcontext.LoadConsoleContext(cfg, hub); err != nil {
				return fmt.Errorf("while loading context: %w", err)
			}

			if len(cfg.Crowdsec.ContextToSend) == 0 {
				fmt.Println("No context found on this agent. You can use 'cscli lapi context add' to add context to your alerts.")
				return nil
			}

			dump, err := yaml.Marshal(cfg.Crowdsec.ContextToSend)
			if err != nil {
				return fmt.Errorf("unable to show context status: %w", err)
			}

			fmt.Print(string(dump))

			return nil
		},
	}

	return cmd
}

func (cli *cliLapi) newContextDetectCmd() *cobra.Command {
	var detectAll bool

	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect available fields from the installed parsers",
		Example: `cscli lapi context detect --all
cscli lapi context detect crowdsecurity/sshd-logs
		`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cli.cfg()
			if !detectAll && len(args) == 0 {
				_ = cmd.Help()
				return errors.New("please provide parsers to detect or --all flag")
			}

			// to avoid all the log.Info from the loaders functions
			log.SetLevel(log.WarnLevel)

			if err := exprhelpers.Init(nil); err != nil {
				return fmt.Errorf("failed to init expr helpers: %w", err)
			}

			hub, err := require.Hub(cfg, nil)
			if err != nil {
				return err
			}

			csParsers := parser.NewParsers(hub)
			if csParsers, err = parser.LoadParsers(cfg, csParsers); err != nil {
				return fmt.Errorf("unable to load parsers: %w", err)
			}

			fieldByParsers := make(map[string][]string)
			for _, node := range csParsers.Nodes {
				if !detectAll && !slices.Contains(args, node.Name) {
					continue
				}
				if !detectAll {
					args = removeFromSlice(node.Name, args)
				}
				fieldByParsers[node.Name] = make([]string, 0)
				fieldByParsers[node.Name] = detectNode(node, *csParsers.Ctx)

				subNodeFields := detectSubNode(node, *csParsers.Ctx)
				for _, field := range subNodeFields {
					if !slices.Contains(fieldByParsers[node.Name], field) {
						fieldByParsers[node.Name] = append(fieldByParsers[node.Name], field)
					}
				}
			}

			fmt.Printf("Acquisition :\n\n")
			fmt.Printf("  - evt.Line.Module\n")
			fmt.Printf("  - evt.Line.Raw\n")
			fmt.Printf("  - evt.Line.Src\n")
			fmt.Println()

			parsersKey := make([]string, 0)
			for k := range fieldByParsers {
				parsersKey = append(parsersKey, k)
			}
			sort.Strings(parsersKey)

			for _, k := range parsersKey {
				if len(fieldByParsers[k]) == 0 {
					continue
				}
				fmt.Printf("%s :\n\n", k)
				values := fieldByParsers[k]
				sort.Strings(values)
				for _, value := range values {
					fmt.Printf("  - %s\n", value)
				}
				fmt.Println()
			}

			if len(args) > 0 {
				for _, parserNotFound := range args {
					log.Errorf("parser '%s' not found, can't detect fields", parserNotFound)
				}
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&detectAll, "all", "a", false, "Detect evt field for all installed parser")

	return cmd
}

func (cli *cliLapi) newContextDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "delete",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			filePath := cli.cfg().Crowdsec.ConsoleContextPath
			if filePath == "" {
				filePath = "the context file"
			}

			return fmt.Errorf("command 'delete' has been removed, please manually edit %s", filePath)
		},
	}

	return cmd
}

func (cli *cliLapi) newContextCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "context [command]",
		Short:             "Manage context to send with alerts",
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := cfg.LoadCrowdsec(); err != nil {
				fileNotFoundMessage := fmt.Sprintf("failed to open context file: open %s: no such file or directory", cfg.Crowdsec.ConsoleContextPath)
				if err.Error() != fileNotFoundMessage {
					return fmt.Errorf("unable to load CrowdSec agent configuration: %w", err)
				}
			}
			if cfg.DisableAgent {
				return errors.New("agent is disabled and lapi context can only be used on the agent")
			}

			return nil
		},
	}

	cmd.AddCommand(cli.newContextAddCmd())
	cmd.AddCommand(cli.newContextStatusCmd())
	cmd.AddCommand(cli.newContextDetectCmd())
	cmd.AddCommand(cli.newContextDeleteCmd())

	return cmd
}

func detectStaticField(grokStatics []parser.ExtraField) []string {
	ret := make([]string, 0)

	for _, static := range grokStatics {
		if static.Parsed != "" {
			fieldName := "evt.Parsed." + static.Parsed
			if !slices.Contains(ret, fieldName) {
				ret = append(ret, fieldName)
			}
		}

		if static.Meta != "" {
			fieldName := "evt.Meta." + static.Meta
			if !slices.Contains(ret, fieldName) {
				ret = append(ret, fieldName)
			}
		}

		if static.TargetByName != "" {
			fieldName := static.TargetByName
			if !strings.HasPrefix(fieldName, "evt.") {
				fieldName = "evt." + fieldName
			}

			if !slices.Contains(ret, fieldName) {
				ret = append(ret, fieldName)
			}
		}
	}

	return ret
}

func detectNode(node parser.Node, parserCTX parser.UnixParserCtx) []string {
	ret := make([]string, 0)

	if node.Grok.RunTimeRegexp != nil {
		for _, capturedField := range node.Grok.RunTimeRegexp.Names() {
			fieldName := "evt.Parsed." + capturedField
			if !slices.Contains(ret, fieldName) {
				ret = append(ret, fieldName)
			}
		}
	}

	if node.Grok.RegexpName != "" {
		grokCompiled, err := parserCTX.Grok.Get(node.Grok.RegexpName)
		// ignore error (parser does not exist?)
		if err == nil {
			for _, capturedField := range grokCompiled.Names() {
				fieldName := "evt.Parsed." + capturedField
				if !slices.Contains(ret, fieldName) {
					ret = append(ret, fieldName)
				}
			}
		}
	}

	if len(node.Grok.Statics) > 0 {
		staticsField := detectStaticField(node.Grok.Statics)
		for _, staticField := range staticsField {
			if !slices.Contains(ret, staticField) {
				ret = append(ret, staticField)
			}
		}
	}

	if len(node.Statics) > 0 {
		staticsField := detectStaticField(node.Statics)
		for _, staticField := range staticsField {
			if !slices.Contains(ret, staticField) {
				ret = append(ret, staticField)
			}
		}
	}

	return ret
}

func detectSubNode(node parser.Node, parserCTX parser.UnixParserCtx) []string {
	ret := make([]string, 0)

	for _, subnode := range node.LeavesNodes {
		if subnode.Grok.RunTimeRegexp != nil {
			for _, capturedField := range subnode.Grok.RunTimeRegexp.Names() {
				fieldName := "evt.Parsed." + capturedField
				if !slices.Contains(ret, fieldName) {
					ret = append(ret, fieldName)
				}
			}
		}

		if subnode.Grok.RegexpName != "" {
			grokCompiled, err := parserCTX.Grok.Get(subnode.Grok.RegexpName)
			if err == nil {
				// ignore error (parser does not exist?)
				for _, capturedField := range grokCompiled.Names() {
					fieldName := "evt.Parsed." + capturedField
					if !slices.Contains(ret, fieldName) {
						ret = append(ret, fieldName)
					}
				}
			}
		}

		if len(subnode.Grok.Statics) > 0 {
			staticsField := detectStaticField(subnode.Grok.Statics)
			for _, staticField := range staticsField {
				if !slices.Contains(ret, staticField) {
					ret = append(ret, staticField)
				}
			}
		}

		if len(subnode.Statics) > 0 {
			staticsField := detectStaticField(subnode.Statics)
			for _, staticField := range staticsField {
				if !slices.Contains(ret, staticField) {
					ret = append(ret, staticField)
				}
			}
		}
	}

	return ret
}
