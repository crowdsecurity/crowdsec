package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type CommandHelp struct {
	Use     string
	Short   string
	Long    string
	Example string
}

type ItemType struct {
	Name        string
	Singular    string
	Help        CommandHelp
	InstallHelp CommandHelp
	RemoveHelp  CommandHelp
	UpgradeHelp CommandHelp
	InspectHelp CommandHelp
	ListHelp    CommandHelp
}

var ItemTypes = map[string]ItemType{
	"parsers": {
		Name:     "parsers",
		Singular: "parser",
		Help: CommandHelp{
			Use:   "parsers <action> [parser]...",
			Short: "Manage hub parsers",
			Example: `cscli parsers list -a
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers inspect crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs
`,
		},
		InstallHelp: CommandHelp{
			Use:     "install <parser>...",
			Short:   "Install given parser(s)",
			Long:    `Fetch and install one or more parsers from the hub`,
			Example: `cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		RemoveHelp: CommandHelp{
			Use:     "remove <parser>...",
			Short:   "Remove given parser(s)",
			Long:    `Remove one or more parsers`,
			Example: `cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		UpgradeHelp: CommandHelp{
			Use:     "upgrade <parser>...",
			Short:   "Upgrade given parser(s)",
			Long:    `Fetch and upgrade one or more parsers from the hub`,
			Example: `cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		InspectHelp: CommandHelp{
			Use:     "inspect <parser>",
			Short:   "Inspect a parser",
			Long:    `Inspect a parser`,
			Example: `cscli parsers inspect crowdsecurity/httpd-logs crowdsecurity/sshd-logs`,
		},
		ListHelp: CommandHelp{
			Use:   "list [parser... | -a]",
			Short: "List parsers",
			Long:  `List of installed/available/specified parsers`,
			Example: `cscli parsers list
cscli parsers list -a
cscli parsers list crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
	},
	"postoverflows": {
		Name:     "postoverflows",
		Singular: "postoverflow",
		Help: CommandHelp{
			Use:   "postoverflows <action> [postoverflow]...",
			Short: "Manage hub postoverflows",
			Example: `cscli postoverflows list -a
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns
`,
		},
		InstallHelp: CommandHelp{
			Use:     "install <postoverflow>...",
			Short:   "Install given postoverflow(s)",
			Long:    `Fetch and install one or more postoverflows from the hub`,
			Example: `cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		RemoveHelp: CommandHelp{
			Use:     "remove <postoverflow>...",
			Short:   "Remove given postoverflow(s)",
			Long:    `remove one or more postoverflows from the hub`,
			Example: `cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		UpgradeHelp: CommandHelp{
			Use:     "upgrade <postoverflow>...",
			Short:   "Upgrade given postoverflow(s)",
			Long:    `Fetch and upgrade one or more postoverflows from the hub`,
			Example: `cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		InspectHelp: CommandHelp{
			Use:     "inspect <postoverflow>",
			Short:   "Inspect a postoverflow",
			Long:    `Inspect a postoverflow`,
			Example: `cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		ListHelp: CommandHelp{
			Use:   "list [postoverflow]...",
			Short: "List postoverflows",
			Long:  `List of installed/available/specified postoverflows`,
			Example: `cscli postoverflows list
cscli postoverflows list -a
cscli postoverflows list crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
	},
	"scenarios": {
		Name:     "scenarios",
		Singular: "scenario",
		Help: CommandHelp{
			Use:   "scenarios <action> [scenario]...",
			Short: "Manage hub scenarios",
			Example: `cscli scenarios list -a
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing
`,
		},
		InstallHelp: CommandHelp{
			Use:     "install <scenario>...",
			Short:   "Install given scenario(s)",
			Long:    `Fetch and install one or more scenarios from the hub`,
			Example: `cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		RemoveHelp: CommandHelp{
			Use:     "remove <scenario>...",
			Short:   "Remove given scenario(s)",
			Long:    `remove one or more scenarios`,
			Example: `cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		UpgradeHelp: CommandHelp{
			Use:     "upgrade <scenario>...",
			Short:   "Upgrade given scenario(s)",
			Long:    `Fetch and upgrade one or more scenarios from the hub`,
			Example: `cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		InspectHelp: CommandHelp{
			Use:     "inspect <scenario>",
			Short:   "Inspect a scenario",
			Long:    `Inspect a scenario`,
			Example: `cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		ListHelp: CommandHelp{
			Use:   "list [scenario]...",
			Short: "List scenarios",
			Long:  `List of installed/available/specified scenarios`,
			Example: `cscli scenarios list
cscli scenarios list -a
cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
	},
	"collections": {
		Name:     "collections",
		Singular: "collection",
		Help: CommandHelp{
			Use:   "collections <action> [collection]...",
			Short: "Manage hub collections",
			Example: `cscli collections list -a
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables
cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables
`,
		},
		InstallHelp: CommandHelp{
			Use:     "install <collection>...",
			Short:   "Install given collection(s)",
			Long:    `Fetch and install one or more collections from hub`,
			Example: `cscli collections install crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		RemoveHelp: CommandHelp{
			Use:     "remove <collection>...",
			Short:   "Remove given collection(s)",
			Long:    `Remove one or more collections`,
			Example: `cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		UpgradeHelp: CommandHelp{
			Use:     "upgrade <collection>...",
			Short:   "Upgrade given collection(s)",
			Long:    `Fetch and upgrade one or more collections from the hub`,
			Example: `cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		InspectHelp: CommandHelp{
			Use:     "inspect <collection>...",
			Short:   "Inspect given collection(s)",
			Long:    `Inspect one or more collections`,
			Example: `cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		ListHelp: CommandHelp{
			Use:   "list [collection... | -a]",
			Short: "List collections",
			Long:  `List of installed/available/specified collections`,
			Example: `cscli collections list
cscli collections list -a
cscli collections list crowdsecurity/http-cve crowdsecurity/iptables`,
		},
	},
}

func NewItemsCmd(typeName string) *cobra.Command {
	it := ItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               it.Help.Use,
		Short:             it.Help.Short,
		Long:              it.Help.Long,
		Example:           it.Help.Example,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{it.Singular},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if _, err := require.Hub(csConfig); err != nil {
				return err
			}

			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cmd.Name() == "inspect" || cmd.Name() == "list" {
				return
			}
			log.Infof(ReloadMessage())
		},
	}

	cmd.AddCommand(NewItemsInstallCmd(typeName))
	cmd.AddCommand(NewItemsRemoveCmd(typeName))
	cmd.AddCommand(NewItemsUpgradeCmd(typeName))
	cmd.AddCommand(NewItemsInspectCmd(typeName))
	cmd.AddCommand(NewItemsListCmd(typeName))

	return cmd
}

func itemsInstallRunner(it ItemType) func(cmd *cobra.Command, args []string) error {
	run := func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		downloadOnly, err := flags.GetBool("download-only")
		if err != nil {
			return err
		}

		force, err := flags.GetBool("force")
		if err != nil {
			return err
		}

		ignoreError, err := flags.GetBool("ignore")
		if err != nil {
			return err
		}

		hub, err := cwhub.GetHub()
		if err != nil {
			return err
		}

		for _, name := range args {
			t := hub.GetItem(it.Name, name)
			if t == nil {
				nearestItem, score := GetDistance(it.Name, name)
				Suggest(it.Name, name, nearestItem.Name, score, ignoreError)

				continue
			}

			if err := hub.InstallItem(name, it.Name, force, downloadOnly); err != nil {
				if !ignoreError {
					return fmt.Errorf("error while installing '%s': %w", name, err)
				}
				log.Errorf("Error while installing '%s': %s", name, err)
			}
		}
		return nil
	}

	return run
}

func NewItemsInstallCmd(typeName string) *cobra.Command {
	it := ItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               it.InstallHelp.Use,
		Short:             it.InstallHelp.Short,
		Long:              it.InstallHelp.Long,
		Example:           it.InstallHelp.Example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(typeName, args, toComplete)
		},
		RunE: itemsInstallRunner(it),
	}

	flags := cmd.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, fmt.Sprintf("Ignore errors when installing multiple %s", it.Name))

	return cmd
}

func itemsRemoveRunner(it ItemType) func(cmd *cobra.Command, args []string) error {
	run := func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		purge, err := flags.GetBool("purge")
		if err != nil {
			return err
		}

		force, err := flags.GetBool("force")
		if err != nil {
			return err
		}

		all, err := flags.GetBool("all")
		if err != nil {
			return err
		}

		hub, err := cwhub.GetHub()
		if err != nil {
			return err
		}

		if all {
			err := hub.RemoveMany(it.Name, "", all, purge, force)
			if err != nil {
				return err
			}

			return nil
		}

		if len(args) == 0 {
			return fmt.Errorf("specify at least one %s to remove or '--all'", it.Singular)
		}

		for _, name := range args {
			if !force {
				item := hub.GetItem(it.Name, name)
				if item == nil {
					// XXX: this should be in GetItem?
					return fmt.Errorf("can't find '%s' in %s", name, it.Name)
				}
				if len(item.BelongsToCollections) > 0 {
					log.Warningf("%s belongs to collections: %s", name, item.BelongsToCollections)
					log.Warningf("Run 'sudo cscli %s remove %s --force' if you want to force remove this %s", it.Name, name, it.Singular)
					continue
				}
			}

			err := hub.RemoveMany(it.Name, name, all, purge, force)
			if err != nil {
				return err
			}
		}

		return nil
	}
	return run
}

func NewItemsRemoveCmd(typeName string) *cobra.Command {
	it := ItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               it.RemoveHelp.Use,
		Short:             it.RemoveHelp.Short,
		Long:              it.RemoveHelp.Long,
		Example:           it.RemoveHelp.Example,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(it.Name, args, toComplete)
		},
		RunE: itemsRemoveRunner(it),
	}

	flags := cmd.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, fmt.Sprintf("Remove all the %s", it.Name))

	return cmd
}

func itemsUpgradeRunner(it ItemType) func(cmd *cobra.Command, args []string) error {
	run := func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		force, err := flags.GetBool("force")
		if err != nil {
			return err
		}

		all, err := flags.GetBool("all")
		if err != nil {
			return err
		}

		hub, err := cwhub.GetHub()
		if err != nil {
			return err
		}

		if all {
			if err := hub.UpgradeConfig(it.Name, "", force); err != nil {
				return err
			}
			return nil
		}

		if len(args) == 0 {
			return fmt.Errorf("specify at least one %s to upgrade or '--all'", it.Singular)
		}

		for _, name := range args {
			if err := hub.UpgradeConfig(it.Name, name, force); err != nil {
				return err
			}
		}

		return nil
	}

	return run
}

func NewItemsUpgradeCmd(typeName string) *cobra.Command {
	it := ItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               it.UpgradeHelp.Use,
		Short:             it.UpgradeHelp.Short,
		Long:              it.UpgradeHelp.Long,
		Example:           it.UpgradeHelp.Example,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(it.Name, args, toComplete)
		},
		RunE: itemsUpgradeRunner(it),
	}

	flags := cmd.Flags()
	flags.BoolP("all", "a", false, fmt.Sprintf("Upgrade all the %s", it.Name))
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmd
}

func itemsInspectRunner(it ItemType) func(cmd *cobra.Command, args []string) error {
	run := func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		url, err := flags.GetString("url")
		if err != nil {
			return err
		}

		if url != "" {
			csConfig.Cscli.PrometheusUrl = url
		}

		noMetrics, err := flags.GetBool("no-metrics")
		if err != nil {
			return err
		}

		for _, name := range args {
			if err = InspectItem(name, it.Name, noMetrics); err != nil {
				return err
			}
		}

		return nil
	}

	return run
}

func NewItemsInspectCmd(typeName string) *cobra.Command {
	it := ItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               it.InspectHelp.Use,
		Short:             it.InspectHelp.Short,
		Long:              it.InspectHelp.Long,
		Example:           it.InspectHelp.Example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(it.Name, args, toComplete)
		},
		RunE: itemsInspectRunner(it),
	}

	flags := cmd.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmd
}

func itemsListRunner(it ItemType) func(cmd *cobra.Command, args []string) error {
	run := func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		all, err := flags.GetBool("all")
		if err != nil {
			return err
		}

		if err = ListItems(color.Output, []string{it.Name}, args, false, true, all); err != nil {
			return err
		}

		return nil
	}

	return run
}

func NewItemsListCmd(typeName string) *cobra.Command {
	it := ItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               it.ListHelp.Use,
		Short:             it.ListHelp.Short,
		Long:              it.ListHelp.Long,
		Example:           it.ListHelp.Example,
		DisableAutoGenTag: true,
		RunE:              itemsListRunner(it),
	}

	flags := cmd.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmd
}
