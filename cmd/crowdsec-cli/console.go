package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func NewConsoleCmd() *cobra.Command {
	var cmdConsole = &cobra.Command{
		Use:               "console [action]",
		Short:             "Manage interaction with Crowdsec console (https://app.crowdsec.net)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			parentCmd := cmd.Parent()

			// if the command is "cscli console context", only the agent needs to be loaded
			switch parentCmd.Name() {
			case "context":
				if err := csConfig.LoadCrowdsec(); err != nil {
					log.Fatalf("Unable to load CrowdSec Agent: %s", err)
				}
			// for all the other `cscli console` command, only the LAPI is needed
			default:
				if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
					var fdErr *fs.PathError
					if errors.As(err, &fdErr) {
						log.Fatalf("Unable to load Local API : %s", fdErr)
					}
					if err != nil {
						log.Fatalf("Unable to load required Local API Configuration : %s", err)
					}
					log.Fatal("Local API is disabled, please run this command on the local API machine")
				}
				if csConfig.DisableAPI {
					log.Fatal("Local API is disabled, please run this command on the local API machine")
				}
				if csConfig.API.Server.OnlineClient == nil {
					log.Fatalf("No configuration for Central API (CAPI) in '%s'", *csConfig.FilePath)
				}
				if csConfig.API.Server.OnlineClient.Credentials == nil {
					log.Fatal("You must configure Central API (CAPI) with `cscli capi register` before accessing console features.")
				}
			}
			return nil
		},
	}

	name := ""
	overwrite := false
	tags := []string{}

	cmdEnroll := &cobra.Command{
		Use:   "enroll [enroll-key]",
		Short: "Enroll this instance to https://app.crowdsec.net [requires local API]",
		Long: `
Enroll this instance to https://app.crowdsec.net
		
You can get your enrollment key by creating an account on https://app.crowdsec.net.
After running this command your will need to validate the enrollment in the webapp.`,
		Example: `cscli console enroll YOUR-ENROLL-KEY
		cscli console enroll --name [instance_name] YOUR-ENROLL-KEY
		cscli console enroll --name [instance_name] --tags [tag_1] --tags [tag_2] YOUR-ENROLL-KEY
`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			apiURL, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("Could not parse CAPI URL : %s", err)
			}

			if err := csConfig.LoadHub(); err != nil {
				log.Fatal(err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to load hub index : %s", err)
				log.Info("Run 'sudo cscli hub update' to get the hub index")
			}

			scenarios, err := cwhub.GetInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err)
			}

			if len(scenarios) == 0 {
				scenarios = make([]string, 0)
			}

			c, _ := apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:      password,
				Scenarios:     scenarios,
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiURL,
				VersionPrefix: "v2",
			})
			resp, err := c.Auth.EnrollWatcher(context.Background(), args[0], name, tags, overwrite)
			if err != nil {
				log.Fatalf("Could not enroll instance: %s", err)
			}
			if resp.Response.StatusCode == 200 && !overwrite {
				log.Warning("Instance already enrolled. You can use '--overwrite' to force enroll")
				return
			}

			SetConsoleOpts(csconfig.CONSOLE_CONFIGS, true)
			if err := csConfig.API.Server.DumpConsoleConfig(); err != nil {
				log.Fatalf("failed writing console config : %s", err)
			}
			log.Infof("Enabled tainted&manual alerts sharing, see 'cscli console status'.")
			log.Infof("Watcher successfully enrolled. Visit https://app.crowdsec.net to accept it.")
			log.Infof("Please restart crowdsec after accepting the enrollment.")
		},
	}
	cmdEnroll.Flags().StringVarP(&name, "name", "n", "", "Name to display in the console")
	cmdEnroll.Flags().BoolVarP(&overwrite, "overwrite", "", false, "Force enroll the instance")
	cmdEnroll.Flags().StringSliceVarP(&tags, "tags", "t", tags, "Tags to display in the console")
	cmdConsole.AddCommand(cmdEnroll)

	var enableAll, disableAll bool

	cmdEnable := &cobra.Command{
		Use:     "enable [feature-flag]",
		Short:   "Enable a feature flag",
		Example: "enable tainted",
		Long: `
Enable given information push to the central API. Allows to empower the console`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if enableAll {
				SetConsoleOpts(csconfig.CONSOLE_CONFIGS, true)
				log.Infof("All features have been enabled successfully")
			} else {
				if len(args) == 0 {
					log.Fatalf("You must specify at least one feature to enable")
				}
				SetConsoleOpts(args, true)
				log.Infof("%v have been enabled", args)
			}
			if err := csConfig.API.Server.DumpConsoleConfig(); err != nil {
				log.Fatalf("failed writing console config : %s", err)
			}
			log.Infof(ReloadMessage())
		},
	}
	cmdEnable.Flags().BoolVarP(&enableAll, "all", "a", false, "Enable all feature flags")
	cmdConsole.AddCommand(cmdEnable)

	cmdDisable := &cobra.Command{
		Use:     "disable [feature-flag]",
		Short:   "Disable a feature flag",
		Example: "disable tainted",
		Long: `
Disable given information push to the central API.`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if disableAll {
				SetConsoleOpts(csconfig.CONSOLE_CONFIGS, false)
			} else {
				SetConsoleOpts(args, false)
			}

			if err := csConfig.API.Server.DumpConsoleConfig(); err != nil {
				log.Fatalf("failed writing console config : %s", err)
			}
			if disableAll {
				log.Infof("All features have been disabled")
			} else {
				log.Infof("%v have been disabled", args)
			}
			log.Infof(ReloadMessage())
		},
	}
	cmdDisable.Flags().BoolVarP(&disableAll, "all", "a", false, "Enable all feature flags")
	cmdConsole.AddCommand(cmdDisable)

	cmdConsoleStatus := &cobra.Command{
		Use:               "status [feature-flag]",
		Short:             "Shows status of one or all feature flags",
		Example:           "status tainted",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			switch csConfig.Cscli.Output {
			case "human":
				cmdConsoleStatusTable(color.Output, *csConfig)
			case "json":
				data, err := json.MarshalIndent(csConfig.API.Server.ConsoleConfig, "", "  ")
				if err != nil {
					log.Fatalf("failed to marshal configuration: %s", err)
				}
				fmt.Printf("%s\n", string(data))
			case "raw":
				csvwriter := csv.NewWriter(os.Stdout)
				err := csvwriter.Write([]string{"option", "enabled"})
				if err != nil {
					log.Fatal(err)
				}

				rows := [][]string{
					{"share_manual_decisions", fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareManualDecisions)},
					{"share_custom", fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios)},
					{"share_tainted", fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios)},
					{"share_context", fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareContext)},
				}
				for _, row := range rows {
					err = csvwriter.Write(row)
					if err != nil {
						log.Fatal(err)
					}
				}
				csvwriter.Flush()
			}
		},
	}

	cmdConsole.AddCommand(cmdConsoleStatus)

	cmdContext := &cobra.Command{
		Use:               "context [feature-flag]",
		Short:             "Manage context to send with alerts",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			printHelp(cmd)
		},
	}

	var keyToAdd string
	var valuesToAdd []string
	cmdContextAdd := &cobra.Command{
		Use:   "add",
		Short: "Add context to send with alerts. You must specify the output key with the expr value you want",
		Example: `cscli console context add --key source_ip --value evt.Meta.source_ip
		cscli console context add --key file_source --value evt.Line.Src
		`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if _, ok := csConfig.Crowdsec.ContextToSend[keyToAdd]; !ok {
				csConfig.Crowdsec.ContextToSend[keyToAdd] = make([]string, 0)
				log.Infof("key '%s' added", keyToAdd)
			}
			data := csConfig.Crowdsec.ContextToSend[keyToAdd]
			for _, val := range valuesToAdd {
				if !inSlice(val, data) {
					log.Infof("value '%s' added to key '%s'", val, keyToAdd)
					data = append(data, val)
				}
				csConfig.Crowdsec.ContextToSend[keyToAdd] = data
			}
			if err := csConfig.Crowdsec.DumpContextConfigFile(); err != nil {
				log.Fatalf(err.Error())
			}
		},
	}
	cmdContextAdd.Flags().StringVarP(&keyToAdd, "key", "k", "", "The key of the different values to send")
	cmdContextAdd.Flags().StringSliceVar(&valuesToAdd, "value", []string{}, "The expr fields to associate with the key")
	cmdContextAdd.MarkFlagRequired("key")
	cmdContextAdd.MarkFlagRequired("value")
	cmdContext.AddCommand(cmdContextAdd)

	cmdContextStatus := &cobra.Command{
		Use:               "status",
		Short:             "List context to send with alerts",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			dump, err := yaml.Marshal(csConfig.Crowdsec.ContextToSend)
			if err != nil {
				log.Fatalf("unable to show context status: %s", err)
			}
			fmt.Println(string(dump))

		},
	}
	cmdContext.AddCommand(cmdContextStatus)

	var detectAll bool
	cmdContextDetect := &cobra.Command{
		Use:               "detect",
		Short:             "Detect available fields from the installed parsers",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			if !detectAll && len(args) == 0 {
				log.Infof("Please provide parsers to detect or --all flag.")
				printHelp(cmd)
			}

			// to avoid all the log.Info from the loaders functions
			log.SetLevel(log.ErrorLevel)

			err = exprhelpers.Init(nil)
			if err != nil {
				log.Fatalf("Failed to init expr helpers : %s", err)
			}

			// Populate cwhub package tools
			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to load hub index : %s", err)
			}

			csParsers := parser.NewParsers()
			if csParsers, err = parser.LoadParsers(csConfig, csParsers); err != nil {
				log.Fatalf("unable to load parsers: %s", err)
			}

			fieldByParsers := make(map[string][]string)
			for _, node := range csParsers.Nodes {
				if !detectAll && !inSlice(node.Name, args) {
					continue
				}
				if !detectAll {
					args = removeFromSlice(node.Name, args)
				}
				fieldByParsers[node.Name] = make([]string, 0)
				fieldByParsers[node.Name] = detectNode(node, *csParsers.Ctx)

				subNodeFields := detectSubNode(node, *csParsers.Ctx)
				for _, field := range subNodeFields {
					if !inSlice(field, fieldByParsers[node.Name]) {
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
		},
	}
	cmdContextDetect.Flags().BoolVarP(&detectAll, "all", "a", false, "Detect evt field for all installed parser")
	cmdContext.AddCommand(cmdContextDetect)

	var keysToDelete []string
	var valuesToDelete []string
	cmdContextDelete := &cobra.Command{
		Use:               "delete",
		Short:             "Delete context to send with alerts",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if len(keysToDelete) == 0 && len(valuesToDelete) == 0 {
				log.Fatalf("please provide at least a key or a value to delete")
			}

			for _, key := range keysToDelete {
				if _, ok := csConfig.Crowdsec.ContextToSend[key]; ok {
					delete(csConfig.Crowdsec.ContextToSend, key)
					log.Infof("key '%s' has been removed", key)
				} else {
					log.Warningf("key '%s' doesn't exist", key)
				}
			}

			for _, value := range valuesToDelete {
				valueFound := false
				for key, context := range csConfig.Crowdsec.ContextToSend {
					if inSlice(value, context) {
						valueFound = true
						csConfig.Crowdsec.ContextToSend[key] = removeFromSlice(value, context)
						log.Infof("value '%s' has been removed from key '%s'", value, key)
					}
					if len(csConfig.Crowdsec.ContextToSend[key]) == 0 {
						delete(csConfig.Crowdsec.ContextToSend, key)
					}
				}
				if !valueFound {
					log.Warningf("value '%s' not found", value)
				}
			}

			if err := csConfig.Crowdsec.DumpContextConfigFile(); err != nil {
				log.Fatalf(err.Error())
			}

		},
	}
	cmdContextDelete.Flags().StringSliceVarP(&keysToDelete, "key", "k", []string{}, "The keys to delete")
	cmdContextDelete.Flags().StringSliceVar(&valuesToDelete, "value", []string{}, "The expr fields to delete")
	cmdContext.AddCommand(cmdContextDelete)

	cmdConsole.AddCommand(cmdContext)

	return cmdConsole
}

func SetConsoleOpts(args []string, wanted bool) {
	for _, arg := range args {
		switch arg {
		case csconfig.SEND_CUSTOM_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareCustomScenarios != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios == wanted {
					log.Infof("%s already set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareCustomScenarios = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareCustomScenarios = types.BoolPtr(wanted)
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios == wanted {
					log.Infof("%s already set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios = types.BoolPtr(wanted)
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareManualDecisions != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareManualDecisions == wanted {
					log.Infof("%s already set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareManualDecisions = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareManualDecisions = types.BoolPtr(wanted)
			}
		case csconfig.SEND_CONTEXT:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareContext != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareContext == wanted {
					log.Infof("%s already set to %t", csconfig.SEND_CONTEXT, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_CONTEXT, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareContext = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CONTEXT, wanted)
				csConfig.API.Server.ConsoleConfig.ShareContext = types.BoolPtr(wanted)
			}
		default:
			log.Fatalf("unknown flag %s", arg)
		}
	}

}

func detectStaticField(GrokStatics []types.ExtraField) []string {
	ret := make([]string, 0)
	for _, static := range GrokStatics {
		if static.Parsed != "" {
			fieldName := fmt.Sprintf("evt.Parsed.%s", static.Parsed)
			if !inSlice(fieldName, ret) {
				ret = append(ret, fieldName)
			}
		}
		if static.Meta != "" {
			fieldName := fmt.Sprintf("evt.Meta.%s", static.Meta)
			if !inSlice(fieldName, ret) {
				ret = append(ret, fieldName)
			}
		}
		if static.TargetByName != "" {
			fieldName := static.TargetByName
			if !strings.HasPrefix(fieldName, "evt.") {
				fieldName = "evt." + fieldName
			}
			if !inSlice(fieldName, ret) {
				ret = append(ret, fieldName)
			}
		}
	}

	return ret
}

func detectNode(node parser.Node, parserCTX parser.UnixParserCtx) []string {
	var ret = make([]string, 0)
	if node.Grok.RunTimeRegexp != nil {
		for _, capturedField := range node.Grok.RunTimeRegexp.Names() {
			fieldName := fmt.Sprintf("evt.Parsed.%s", capturedField)
			if !inSlice(fieldName, ret) {
				ret = append(ret, fieldName)
			}
		}
	}

	if node.Grok.RegexpName != "" {
		grokCompiled, err := parserCTX.Grok.Get(node.Grok.RegexpName)
		if err != nil {
			log.Warningf("Can't get subgrok: %s", err)
		}
		for _, capturedField := range grokCompiled.Names() {
			fieldName := fmt.Sprintf("evt.Parsed.%s", capturedField)
			if !inSlice(fieldName, ret) {
				ret = append(ret, fieldName)
			}
		}
	}

	if len(node.Grok.Statics) > 0 {
		staticsField := detectStaticField(node.Grok.Statics)
		for _, staticField := range staticsField {
			if !inSlice(staticField, ret) {
				ret = append(ret, staticField)
			}
		}
	}

	if len(node.Statics) > 0 {
		staticsField := detectStaticField(node.Statics)
		for _, staticField := range staticsField {
			if !inSlice(staticField, ret) {
				ret = append(ret, staticField)
			}
		}
	}

	return ret
}

func detectSubNode(node parser.Node, parserCTX parser.UnixParserCtx) []string {
	var ret = make([]string, 0)

	for _, subnode := range node.LeavesNodes {
		if subnode.Grok.RunTimeRegexp != nil {
			for _, capturedField := range subnode.Grok.RunTimeRegexp.Names() {
				fieldName := fmt.Sprintf("evt.Parsed.%s", capturedField)
				if !inSlice(fieldName, ret) {
					ret = append(ret, fieldName)
				}
			}
		}
		if subnode.Grok.RegexpName != "" {
			grokCompiled, err := parserCTX.Grok.Get(subnode.Grok.RegexpName)
			if err != nil {
				log.Warningf("Can't get subgrok: %s", err)
			}
			for _, capturedField := range grokCompiled.Names() {
				fieldName := fmt.Sprintf("evt.Parsed.%s", capturedField)
				if !inSlice(fieldName, ret) {
					ret = append(ret, fieldName)
				}
			}
		}

		if len(subnode.Grok.Statics) > 0 {
			staticsField := detectStaticField(subnode.Grok.Statics)
			for _, staticField := range staticsField {
				if !inSlice(staticField, ret) {
					ret = append(ret, staticField)
				}
			}
		}

		if len(subnode.Statics) > 0 {
			staticsField := detectStaticField(subnode.Statics)
			for _, staticField := range staticsField {
				if !inSlice(staticField, ret) {
					ret = append(ret, staticField)
				}
			}
		}
	}

	return ret
}
