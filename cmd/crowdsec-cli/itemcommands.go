package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/coalesce"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type cmdHelp struct {
	// Example is required, the others have a default value
	// generated from the item type
	use     string
	short   string
	long    string
	example string
}

type hubItemType struct {
	name        string // plural, as used in the hub index
	singular    string
	oneOrMore   string // parenthetical pluralizaion: "parser(s)"
	help        cmdHelp
	installHelp cmdHelp
	removeHelp  cmdHelp
	upgradeHelp cmdHelp
	inspectHelp cmdHelp
	listHelp    cmdHelp
}

var hubItemTypes = map[string]hubItemType{
	"parsers": {
		name:      cwhub.PARSERS,
		singular:  "parser",
		oneOrMore: "parser(s)",
		help: cmdHelp{
			example: `cscli parsers list -a
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers inspect crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs
`,
		},
		installHelp: cmdHelp{
			example: `cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		removeHelp: cmdHelp{
			example: `cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		upgradeHelp: cmdHelp{
			example: `cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		inspectHelp: cmdHelp{
			example: `cscli parsers inspect crowdsecurity/httpd-logs crowdsecurity/sshd-logs`,
		},
		listHelp: cmdHelp{
			example: `cscli parsers list
cscli parsers list -a
cscli parsers list crowdsecurity/caddy-logs crowdsecurity/sshd-logs

List only enabled parsers unless "-a" or names are specified.`,
		},
	},
	"postoverflows": {
		name:      cwhub.POSTOVERFLOWS,
		singular:  "postoverflow",
		oneOrMore: "postoverflow(s)",
		help: cmdHelp{
			example: `cscli postoverflows list -a
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns
`,
		},
		installHelp: cmdHelp{
			example: `cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		removeHelp: cmdHelp{
			example: `cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		upgradeHelp: cmdHelp{
			example: `cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		inspectHelp: cmdHelp{
			example: `cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		listHelp: cmdHelp{
			example: `cscli postoverflows list
cscli postoverflows list -a
cscli postoverflows list crowdsecurity/cdn-whitelist crowdsecurity/rdns

List only enabled postoverflows unless "-a" or names are specified.`,
		},
	},
	"scenarios": {
		name:      cwhub.SCENARIOS,
		singular:  "scenario",
		oneOrMore: "scenario(s)",
		help: cmdHelp{
			example: `cscli scenarios list -a
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing
`,
		},
		installHelp: cmdHelp{
			example: `cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		removeHelp: cmdHelp{
			example: `cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		upgradeHelp: cmdHelp{
			example: `cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		inspectHelp: cmdHelp{
			example: `cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		listHelp: cmdHelp{
			example: `cscli scenarios list
cscli scenarios list -a
cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/http-probing

List only enabled scenarios unless "-a" or names are specified.`,
		},
	},
	"appsec-rules": {
		name:      "appsec-rules",
		singular:  "appsec-rule",
		oneOrMore: "appsec-rule(s)",
		help: cmdHelp{
			example: `cscli appsec-rules list -a
cscli appsec-rules install crowdsecurity/crs
cscli appsec-rules inspect crowdsecurity/crs
cscli appsec-rules upgrade crowdsecurity/crs
cscli appsec-rules remove crowdsecurity/crs
`,
		},
		installHelp: cmdHelp{
			example: `cscli appsec-rules install crowdsecurity/crs`,
		},
		removeHelp: cmdHelp{
			example: `cscli appsec-rules remove crowdsecurity/crs`,
		},
		upgradeHelp: cmdHelp{
			example: `cscli appsec-rules upgrade crowdsecurity/crs`,
		},
		inspectHelp: cmdHelp{
			example: `cscli appsec-rules inspect crowdsecurity/crs`,
		},
		listHelp: cmdHelp{
			example: `cscli appsec-rules list
cscli appsec-rules list -a
cscli appsec-rules list crowdsecurity/crs`,
		},
	},
	"appsec-configs": {
		name:      "appsec-configs",
		singular:  "appsec-config",
		oneOrMore: "appsec-config(s)",
		help: cmdHelp{
			example: `cscli appsec-configs list -a
cscli appsec-configs install crowdsecurity/vpatch
cscli appsec-configs inspect crowdsecurity/vpatch
cscli appsec-configs upgrade crowdsecurity/vpatch
cscli appsec-configs remove crowdsecurity/vpatch
`,
		},
		installHelp: cmdHelp{
			example: `cscli appsec-configs install crowdsecurity/vpatch`,
		},
		removeHelp: cmdHelp{
			example: `cscli appsec-configs remove crowdsecurity/vpatch`,
		},
		upgradeHelp: cmdHelp{
			example: `cscli appsec-configs upgrade crowdsecurity/vpatch`,
		},
		inspectHelp: cmdHelp{
			example: `cscli appsec-configs inspect crowdsecurity/vpatch`,
		},
		listHelp: cmdHelp{
			example: `cscli appsec-configs list
cscli appsec-configs list -a
cscli appsec-configs list crowdsecurity/vpatch`,
		},
	},
	"collections": {
		name:      cwhub.COLLECTIONS,
		singular:  "collection",
		oneOrMore: "collection(s)",
		help: cmdHelp{
			example: `cscli collections list -a
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables
cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables
`,
		},
		installHelp: cmdHelp{
			example: `cscli collections install crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		removeHelp: cmdHelp{
			example: `cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		upgradeHelp: cmdHelp{
			example: `cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		inspectHelp: cmdHelp{
			example: `cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		listHelp: cmdHelp{
			example: `cscli collections list
cscli collections list -a
cscli collections list crowdsecurity/http-cve crowdsecurity/iptables

List only enabled collections unless "-a" or names are specified.`,
		},
	},
}

func NewItemsCmd(typeName string) *cobra.Command {
	it := hubItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               coalesce.String(it.help.use, fmt.Sprintf("%s <action> [item]...", it.name)),
		Short:             coalesce.String(it.help.short, fmt.Sprintf("Manage hub %s", it.name)),
		Long:              it.help.long,
		Example:           it.help.example,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{it.singular},
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(NewItemsInstallCmd(typeName))
	cmd.AddCommand(NewItemsRemoveCmd(typeName))
	cmd.AddCommand(NewItemsUpgradeCmd(typeName))
	cmd.AddCommand(NewItemsInspectCmd(typeName))
	cmd.AddCommand(NewItemsListCmd(typeName))

	return cmd
}

func itemsInstallRunner(it hubItemType) func(cmd *cobra.Command, args []string) error {
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

		hub, err := require.Hub(csConfig, require.RemoteHub(csConfig))
		if err != nil {
			return err
		}

		for _, name := range args {
			item := hub.GetItem(it.name, name)
			if item == nil {
				msg := suggestNearestMessage(hub, it.name, name)
				if !ignoreError {
					return fmt.Errorf(msg)
				}

				log.Errorf(msg)

				continue
			}

			if err := item.Install(force, downloadOnly); err != nil {
				if !ignoreError {
					return fmt.Errorf("error while installing '%s': %w", item.Name, err)
				}
				log.Errorf("Error while installing '%s': %s", item.Name, err)
			}
		}

		log.Infof(ReloadMessage())
		return nil
	}

	return run
}

func NewItemsInstallCmd(typeName string) *cobra.Command {
	it := hubItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               coalesce.String(it.installHelp.use, "install [item]..."),
		Short:             coalesce.String(it.installHelp.short, fmt.Sprintf("Install given %s", it.oneOrMore)),
		Long:              coalesce.String(it.installHelp.long, fmt.Sprintf("Fetch and install one or more %s from the hub", it.name)),
		Example:           it.installHelp.example,
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
	flags.Bool("ignore", false, fmt.Sprintf("Ignore errors when installing multiple %s", it.name))

	return cmd
}

// return the names of the installed parents of an item, used to check if we can remove it
func istalledParentNames(item *cwhub.Item) []string {
	ret := make([]string, 0)

	for _, parent := range item.Ancestors() {
		if parent.State.Installed {
			ret = append(ret, parent.Name)
		}
	}

	return ret
}

func itemsRemoveRunner(it hubItemType) func(cmd *cobra.Command, args []string) error {
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

		hub, err := require.Hub(csConfig, nil)
		if err != nil {
			return err
		}

		if all {
			getter := hub.GetInstalledItems
			if purge {
				getter = hub.GetAllItems
			}

			items, err := getter(it.name)
			if err != nil {
				return err
			}

			removed := 0

			for _, item := range items {
				didRemove, err := item.Remove(purge, force)
				if err != nil {
					return err
				}
				if didRemove {
					log.Infof("Removed %s", item.Name)
					removed++
				}
			}

			log.Infof("Removed %d %s", removed, it.name)
			if removed > 0 {
				log.Infof(ReloadMessage())
			}

			return nil
		}

		if len(args) == 0 {
			return fmt.Errorf("specify at least one %s to remove or '--all'", it.singular)
		}

		removed := 0

		for _, itemName := range args {
			item := hub.GetItem(it.name, itemName)
			if item == nil {
				return fmt.Errorf("can't find '%s' in %s", itemName, it.name)
			}

			parents := istalledParentNames(item)

			if !force && len(parents) > 0 {
				log.Warningf("%s belongs to collections: %s", item.Name, parents)
				log.Warningf("Run 'sudo cscli %s remove %s --force' if you want to force remove this %s", item.Type, item.Name, it.singular)
				continue
			}

			didRemove, err := item.Remove(purge, force)
			if err != nil {
				return err
			}

			if didRemove {
				log.Infof("Removed %s", item.Name)
				removed++
			}
		}

		log.Infof("Removed %d %s", removed, it.name)
		if removed > 0 {
			log.Infof(ReloadMessage())
		}

		return nil
	}
	return run
}

func NewItemsRemoveCmd(typeName string) *cobra.Command {
	it := hubItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               coalesce.String(it.removeHelp.use, "remove [item]..."),
		Short:             coalesce.String(it.removeHelp.short, fmt.Sprintf("Remove given %s", it.oneOrMore)),
		Long:              coalesce.String(it.removeHelp.long, fmt.Sprintf("Remove one or more %s", it.name)),
		Example:           it.removeHelp.example,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(it.name, args, toComplete)
		},
		RunE: itemsRemoveRunner(it),
	}

	flags := cmd.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, fmt.Sprintf("Remove all the %s", it.name))

	return cmd
}

func itemsUpgradeRunner(it hubItemType) func(cmd *cobra.Command, args []string) error {
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

		hub, err := require.Hub(csConfig, require.RemoteHub(csConfig))
		if err != nil {
			return err
		}

		if all {
			items, err := hub.GetInstalledItems(it.name)
			if err != nil {
				return err
			}

			updated := 0

			for _, item := range items {
				didUpdate, err := item.Upgrade(force)
				if err != nil {
					return err
				}
				if didUpdate {
					updated++
				}
			}

			log.Infof("Updated %d %s", updated, it.name)

			if updated > 0 {
				log.Infof(ReloadMessage())
			}

			return nil
		}

		if len(args) == 0 {
			return fmt.Errorf("specify at least one %s to upgrade or '--all'", it.singular)
		}

		updated := 0

		for _, itemName := range args {
			item := hub.GetItem(it.name, itemName)
			if item == nil {
				return fmt.Errorf("can't find '%s' in %s", itemName, it.name)
			}

			didUpdate, err := item.Upgrade(force)
			if err != nil {
				return err
			}

			if didUpdate {
				log.Infof("Updated %s", item.Name)
				updated++
			}
		}
		if updated > 0 {
			log.Infof(ReloadMessage())
		}

		return nil
	}

	return run
}

func NewItemsUpgradeCmd(typeName string) *cobra.Command {
	it := hubItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               coalesce.String(it.upgradeHelp.use, "upgrade [item]..."),
		Short:             coalesce.String(it.upgradeHelp.short, fmt.Sprintf("Upgrade given %s", it.oneOrMore)),
		Long:              coalesce.String(it.upgradeHelp.long, fmt.Sprintf("Fetch and upgrade one or more %s from the hub", it.name)),
		Example:           it.upgradeHelp.example,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(it.name, args, toComplete)
		},
		RunE: itemsUpgradeRunner(it),
	}

	flags := cmd.Flags()
	flags.BoolP("all", "a", false, fmt.Sprintf("Upgrade all the %s", it.name))
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmd
}

func itemsInspectRunner(it hubItemType) func(cmd *cobra.Command, args []string) error {
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

		hub, err := require.Hub(csConfig, nil)
		if err != nil {
			return err
		}

		for _, name := range args {
			item := hub.GetItem(it.name, name)
			if item == nil {
				return fmt.Errorf("can't find '%s' in %s", name, it.name)
			}
			if err = InspectItem(item, !noMetrics); err != nil {
				return err
			}
		}

		return nil
	}

	return run
}

func NewItemsInspectCmd(typeName string) *cobra.Command {
	it := hubItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               coalesce.String(it.inspectHelp.use, "inspect [item]..."),
		Short:             coalesce.String(it.inspectHelp.short, fmt.Sprintf("Inspect given %s", it.oneOrMore)),
		Long:              coalesce.String(it.inspectHelp.long, fmt.Sprintf("Inspect the state of one or more %s", it.name)),
		Example:           it.inspectHelp.example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(it.name, args, toComplete)
		},
		RunE: itemsInspectRunner(it),
	}

	flags := cmd.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmd
}

func itemsListRunner(it hubItemType) func(cmd *cobra.Command, args []string) error {
	run := func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		all, err := flags.GetBool("all")
		if err != nil {
			return err
		}

		hub, err := require.Hub(csConfig, nil)
		if err != nil {
			return err
		}

		items := make(map[string][]*cwhub.Item)

		items[it.name], err = selectItems(hub, it.name, args, !all)
		if err != nil {
			return err
		}

		if err = listItems(color.Output, []string{it.name}, items); err != nil {
			return err
		}

		return nil
	}

	return run
}

func NewItemsListCmd(typeName string) *cobra.Command {
	it := hubItemTypes[typeName]

	cmd := &cobra.Command{
		Use:               coalesce.String(it.listHelp.use, "list [item... | -a]"),
		Short:             coalesce.String(it.listHelp.short, fmt.Sprintf("List %s", it.oneOrMore)),
		Long:              coalesce.String(it.listHelp.long, fmt.Sprintf("List of installed/available/specified %s", it.name)),
		Example:           it.listHelp.example,
		DisableAutoGenTag: true,
		RunE:              itemsListRunner(it),
	}

	flags := cmd.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmd
}
