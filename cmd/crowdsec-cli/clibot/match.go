package clibot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// matchResult is the -o json payload of "cscli bot match".
type matchResult struct {
	Match bool                  `json:"match"`
	Files []string              `json:"files"`
	Bot   *exprhelpers.BotMatch `json:"bot,omitempty"`
}

// botDataFiles returns the "bots" data files declared by the given
// appsec-configs, loading them into the expr datafile registry.
// Only the data: section is parsed: the rest of the config is irrelevant here
// and may reference rules that are not installed.
func botDataFiles(hub *cwhub.Hub, items []*cwhub.Item) ([]string, error) {
	if err := exprhelpers.Init(nil); err != nil {
		return nil, err
	}

	files := []string{}

	for _, item := range items {
		if item.State.LocalPath == "" {
			continue
		}

		content, err := os.ReadFile(item.State.LocalPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read %s: %w", item.State.LocalPath, err)
		}

		var cfg struct {
			Data []*enrichment.DataProvider `yaml:"data"`
		}

		if err := yaml.Unmarshal(content, &cfg); err != nil {
			return nil, fmt.Errorf("unable to parse %s: %w", item.State.LocalPath, err)
		}

		for _, d := range cfg.Data {
			if d.Type != "bots" || d.DestPath == "" {
				continue
			}

			if err := exprhelpers.FileInit(hub.GetDataDir(), d.DestPath, d.Type); err != nil {
				return nil, fmt.Errorf("unable to load data file %s: %w", d.DestPath, err)
			}

			files = append(files, d.DestPath)
		}
	}

	return files, nil
}

func (cli *cliBot) match(out io.Writer, names []string, ip string, userAgent string, path string) error {
	hub, err := require.Hub(cli.cfg(), log.StandardLogger())
	if err != nil {
		return err
	}

	items := []*cwhub.Item{}

	if len(names) == 0 {
		items = hub.GetInstalledByType(cwhub.APPSEC_CONFIGS, true)
	}

	for _, name := range names {
		item := hub.GetItem(cwhub.APPSEC_CONFIGS, name)
		if item == nil {
			return fmt.Errorf("can't find '%s' in %s", name, cwhub.APPSEC_CONFIGS)
		}

		items = append(items, item)
	}

	files, err := botDataFiles(hub, items)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return errors.New("no 'bots' data file declared by the installed appsec-config(s)")
	}

	match, err := exprhelpers.ExplainKnownBot(ip, userAgent, path, files...)
	if err != nil {
		return err
	}

	result := matchResult{Match: match != nil, Files: files, Bot: match}

	switch cli.cfg().Cscli.Output {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		return enc.Encode(result)
	case "raw":
		if match == nil {
			fmt.Fprintln(out, "false")
			return nil
		}

		fmt.Fprintf(out, "true,%s,%s,%s,%s\n", match.Name, match.File, match.Method, match.Detail)

		return nil
	default:
		if match == nil {
			noun := "files"
			if len(files) == 1 {
				noun = "file"
			}

			fmt.Fprintf(out, "no match for %s (checked %d bot data %s)\n", ip, len(files), noun)
			log.Debugf("bot data files checked: %s", strings.Join(files, ", "))

			return nil
		}

		fmt.Fprintf(out, "%s matches bot '%s' (%s: %s) from %s\n", ip, match.Name, match.Method, match.Detail, match.File)

		return nil
	}
}

func (cli *cliBot) newMatchCmd() *cobra.Command {
	var (
		ip        string
		userAgent string
		path      string
	)

	cmd := &cobra.Command{
		Use:   "match [appsec-config]...",
		Short: "Check if a request would be recognized as a known bot",
		Long: `Run the MatchKnownBot() expr helper against the 'bots' data files declared by
the given appsec-configs (all installed ones by default). Reverse DNS is resolved at
runtime, so the result depends on what the local resolver answers.`,
		Example: `cscli bot match --ip 66.249.66.1 --user-agent "Googlebot/2.1"
cscli bot match --ip 1.2.3.4 --path /robots.txt crowdsecurity/appsec-default`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledAppsecConfigs(args, toComplete, cli.cfg)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.match(color.Output, args, ip, userAgent, path)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&ip, "ip", "", "Source IP address of the request")
	flags.StringVar(&userAgent, "user-agent", "", "User-Agent header of the request")
	flags.StringVar(&path, "path", "", "URI path of the request")

	_ = cmd.MarkFlagRequired("ip")

	return cmd
}

func compInstalledAppsecConfigs(_ []string, toComplete string, cfg csconfig.Getter) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(cfg(), nil)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	comp := make([]string, 0)

	for _, item := range hub.GetInstalledByType(cwhub.APPSEC_CONFIGS, true) {
		if strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}

	return comp, cobra.ShellCompDirectiveNoFileComp
}
