package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

var LAPIURLPrefix string = "v1"

func runLapiStatus(cmd *cobra.Command, args []string) error {
	var err error

	password := strfmt.Password(csConfig.API.Client.Credentials.Password)
	apiurl, err := url.Parse(csConfig.API.Client.Credentials.URL)
	login := csConfig.API.Client.Credentials.Login
	if err != nil {
		log.Fatalf("parsing api url ('%s'): %s", apiurl, err)
	}
	if err := csConfig.LoadHub(); err != nil {
		log.Fatal(err)
	}

	if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
		log.Info("Run 'sudo cscli hub update' to get the hub index")
		log.Fatalf("Failed to load hub index : %s", err)
	}
	scenarios, err := cwhub.GetInstalledScenariosAsString()
	if err != nil {
		log.Fatalf("failed to get scenarios : %s", err)
	}

	Client, err = apiclient.NewDefaultClient(apiurl,
		LAPIURLPrefix,
		fmt.Sprintf("crowdsec/%s", version.String()),
		nil)
	if err != nil {
		log.Fatalf("init default client: %s", err)
	}
	t := models.WatcherAuthRequest{
		MachineID: &login,
		Password:  &password,
		Scenarios: scenarios,
	}
	log.Infof("Loaded credentials from %s", csConfig.API.Client.CredentialsFilePath)
	log.Infof("Trying to authenticate with username %s on %s", login, apiurl)
	_, _, err = Client.Auth.AuthenticateWatcher(context.Background(), t)
	if err != nil {
		log.Fatalf("Failed to authenticate to Local API (LAPI) : %s", err)
	} else {
		log.Infof("You can successfully interact with Local API (LAPI)")
	}

	return nil
}

func runLapiRegister(cmd *cobra.Command, args []string) error {
	var err error

	flags := cmd.Flags()

	apiURL, err := flags.GetString("url")
	if err != nil {
		return err
	}

	outputFile, err := flags.GetString("file")
	if err != nil {
		return err
	}

	lapiUser, err := flags.GetString("machine")
	if err != nil {
		return err
	}

	if lapiUser == "" {
		lapiUser, err = generateID("")
		if err != nil {
			log.Fatalf("unable to generate machine id: %s", err)
		}
	}
	password := strfmt.Password(generatePassword(passwordLength))
	if apiURL == "" {
		if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil && csConfig.API.Client.Credentials.URL != "" {
			apiURL = csConfig.API.Client.Credentials.URL
		} else {
			log.Fatalf("No Local API URL. Please provide it in your configuration or with the -u parameter")
		}
	}
	/*URL needs to end with /, but user doesn't care*/
	if !strings.HasSuffix(apiURL, "/") {
		apiURL += "/"
	}
	/*URL needs to start with http://, but user doesn't care*/
	if !strings.HasPrefix(apiURL, "http://") && !strings.HasPrefix(apiURL, "https://") {
		apiURL = "http://" + apiURL
	}
	apiurl, err := url.Parse(apiURL)
	if err != nil {
		log.Fatalf("parsing api url: %s", err)
	}
	_, err = apiclient.RegisterClient(&apiclient.Config{
		MachineID:     lapiUser,
		Password:      password,
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiurl,
		VersionPrefix: LAPIURLPrefix,
	}, nil)

	if err != nil {
		log.Fatalf("api client register: %s", err)
	}

	log.Printf("Successfully registered to Local API (LAPI)")

	var dumpFile string
	if outputFile != "" {
		dumpFile = outputFile
	} else if csConfig.API.Client.CredentialsFilePath != "" {
		dumpFile = csConfig.API.Client.CredentialsFilePath
	} else {
		dumpFile = ""
	}
	apiCfg := csconfig.ApiCredentialsCfg{
		Login:    lapiUser,
		Password: password.String(),
		URL:      apiURL,
	}
	apiConfigDump, err := yaml.Marshal(apiCfg)
	if err != nil {
		log.Fatalf("unable to marshal api credentials: %s", err)
	}
	if dumpFile != "" {
		err = os.WriteFile(dumpFile, apiConfigDump, 0644)
		if err != nil {
			log.Fatalf("write api credentials in '%s' failed: %s", dumpFile, err)
		}
		log.Printf("Local API credentials dumped to '%s'", dumpFile)
	} else {
		fmt.Printf("%s\n", string(apiConfigDump))
	}
	log.Warning(ReloadMessage())

	return nil
}

func NewLapiStatusCmd() *cobra.Command {
	cmdLapiStatus := &cobra.Command{
		Use:               "status",
		Short:             "Check authentication to Local API (LAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE:              runLapiStatus,
	}

	return cmdLapiStatus
}

func NewLapiRegisterCmd() *cobra.Command {
	cmdLapiRegister := &cobra.Command{
		Use:   "register",
		Short: "Register a machine to Local API (LAPI)",
		Long: `Register your machine to the Local API (LAPI).
Keep in mind the machine needs to be validated by an administrator on LAPI side to be effective.`,
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE:              runLapiRegister,
	}

	flags := cmdLapiRegister.Flags()
	flags.StringP("url", "u", "", "URL of the API (ie. http://127.0.0.1)")
	flags.StringP("file", "f", "", "output file destination")
	flags.String("machine", "", "Name of the machine to register with")

	return cmdLapiRegister
}

func NewLapiCmd() *cobra.Command {
	var cmdLapi = &cobra.Command{
		Use:               "lapi [action]",
		Short:             "Manage interaction with Local API (LAPI)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIClient(); err != nil {
				return fmt.Errorf("loading api client: %w", err)
			}
			return nil
		},
	}

	cmdLapi.AddCommand(NewLapiRegisterCmd())
	cmdLapi.AddCommand(NewLapiStatusCmd())
	cmdLapi.AddCommand(NewLapiContextCmd())

	return cmdLapi
}

func NewLapiContextCmd() *cobra.Command {
	cmdContext := &cobra.Command{
		Use:               "context [command]",
		Short:             "Manage context to send with alerts",
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadCrowdsec(); err != nil {
				fileNotFoundMessage := fmt.Sprintf("failed to open context file: open %s: no such file or directory", csConfig.Crowdsec.ConsoleContextPath)
				if err.Error() != fileNotFoundMessage {
					log.Fatalf("Unable to load CrowdSec Agent: %s", err)
				}
			}
			if csConfig.DisableAgent {
				log.Fatalf("Agent is disabled and lapi context can only be used on the agent")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			printHelp(cmd)
		},
	}

	var keyToAdd string
	var valuesToAdd []string
	cmdContextAdd := &cobra.Command{
		Use:   "add",
		Short: "Add context to send with alerts. You must specify the output key with the expr value you want",
		Example: `cscli lapi context add --key source_ip --value evt.Meta.source_ip
cscli lapi context add --key file_source --value evt.Line.Src
		`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := alertcontext.ValidateContextExpr(keyToAdd, valuesToAdd); err != nil {
				log.Fatalf("invalid context configuration :%s", err)
			}
			if _, ok := csConfig.Crowdsec.ContextToSend[keyToAdd]; !ok {
				csConfig.Crowdsec.ContextToSend[keyToAdd] = make([]string, 0)
				log.Infof("key '%s' added", keyToAdd)
			}
			data := csConfig.Crowdsec.ContextToSend[keyToAdd]
			for _, val := range valuesToAdd {
				if !slices.Contains(data, val) {
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
			if len(csConfig.Crowdsec.ContextToSend) == 0 {
				fmt.Println("No context found on this agent. You can use 'cscli lapi context add' to add context to your alerts.")
				return
			}

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
		Use:   "detect",
		Short: "Detect available fields from the installed parsers",
		Example: `cscli lapi context detect --all
cscli lapi context detect crowdsecurity/sshd-logs
		`,
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
		},
	}
	cmdContextDetect.Flags().BoolVarP(&detectAll, "all", "a", false, "Detect evt field for all installed parser")
	cmdContext.AddCommand(cmdContextDetect)

	var keysToDelete []string
	var valuesToDelete []string
	cmdContextDelete := &cobra.Command{
		Use:   "delete",
		Short: "Delete context to send with alerts",
		Example: `cscli lapi context delete --key source_ip
cscli lapi context delete --value evt.Line.Src
		`,
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
					if slices.Contains(context, value) {
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

	return cmdContext
}

func detectStaticField(GrokStatics []parser.ExtraField) []string {
	ret := make([]string, 0)
	for _, static := range GrokStatics {
		if static.Parsed != "" {
			fieldName := fmt.Sprintf("evt.Parsed.%s", static.Parsed)
			if !slices.Contains(ret, fieldName) {
				ret = append(ret, fieldName)
			}
		}
		if static.Meta != "" {
			fieldName := fmt.Sprintf("evt.Meta.%s", static.Meta)
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
	var ret = make([]string, 0)
	if node.Grok.RunTimeRegexp != nil {
		for _, capturedField := range node.Grok.RunTimeRegexp.Names() {
			fieldName := fmt.Sprintf("evt.Parsed.%s", capturedField)
			if !slices.Contains(ret, fieldName) {
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
			if !slices.Contains(ret, fieldName) {
				ret = append(ret, fieldName)
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
	var ret = make([]string, 0)

	for _, subnode := range node.LeavesNodes {
		if subnode.Grok.RunTimeRegexp != nil {
			for _, capturedField := range subnode.Grok.RunTimeRegexp.Names() {
				fieldName := fmt.Sprintf("evt.Parsed.%s", capturedField)
				if !slices.Contains(ret, fieldName) {
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
				if !slices.Contains(ret, fieldName) {
					ret = append(ret, fieldName)
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
