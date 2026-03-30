package cliitem

import (
	"fmt"
	"os"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewAppsecConfig(cfg csconfig.Getter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.APPSEC_CONFIGS,
		singular:  "appsec-config",
		oneOrMore: "appsec-config(s)",
		aliases:   []string{"waf-configs"},
		help: cliHelp{
			example: `cscli waf-configs list -a
cscli waf-configs install crowdsecurity/virtual-patching
cscli waf-configs inspect crowdsecurity/virtual-patching
cscli waf-configs upgrade crowdsecurity/virtual-patching
cscli waf-configs remove crowdsecurity/virtual-patching
`,
		},
		installHelp: cliHelp{
			example: `# Install some waf-configs.
cscli waf-configs install crowdsecurity/virtual-patching

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli waf-configs install crowdsecurity/virtual-patching --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli waf-configs install crowdsecurity/virtual-patching --dry-run -o raw

# Download only, to be installed later.
cscli waf-configs install crowdsecurity/virtual-patching --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli waf-configs install crowdsecurity/virtual-patching --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli waf-configs install crowdsecurity/virtual-patching -i
cscli waf-configs install crowdsecurity/virtual-patching --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some waf-configs.
cscli waf-configs remove crowdsecurity/virtual-patching

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli waf-configs remove crowdsecurity/virtual-patching --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli waf-configs remove crowdsecurity/virtual-patching --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli waf-configs remove crowdsecurity/virtual-patching --purge

# Remove tainted items.
cscli waf-configs remove crowdsecurity/virtual-patching --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli waf-configs remove crowdsecurity/virtual-patching -i
cscli waf-configs remove crowdsecurity/virtual-patching --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some waf-configs. If they are not currently installed, they are downloaded but not installed.
cscli waf-configs upgrade crowdsecurity/virtual-patching

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli waf-configs upgrade crowdsecurity/virtual-patching --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli waf-configs upgrade crowdsecurity/virtual-patching --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli waf-configs upgrade crowdsecurity/virtual-patching --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli waf-configs upgrade crowdsecurity/virtual-patching -i
cscli waf-configs upgrade crowdsecurity/virtual-patching --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state, ancestor collections of waf-configs (installed or not).
cscli waf-configs inspect crowdsecurity/virtual-patching

# If the config is installed, its metrics are collected and shown as well (with an error if crowdsec is not running).
# To avoid this, use --no-metrics.
cscli waf-configs inspect crowdsecurity/virtual-patching --no-metrics

# Display difference between a tainted item and the latest one.
cscli waf-configs inspect crowdsecurity/virtual-patching --diff

# Reverse the above diff
cscli waf-configs inspect crowdsecurity/virtual-patching --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) waf-configs.
cscli waf-configs list

# List all available waf-configs (installed or not).
cscli waf-configs list -a

# List specific waf-configs (installed or not).
cscli waf-configs list crowdsecurity/virtual-patching crowdsecurity/generic-rules`,
		},
	}
}

func NewAppsecRule(cfg csconfig.Getter) *cliItem {
	inspectDetail := func(item *cwhub.Item) error {
		// Only show the converted rules in human mode
		if cfg().Cscli.Output != "human" {
			return nil
		}

		appsecRule := appsec.AppsecCollectionConfig{}

		if item.State.LocalPath == "" {
			return nil
		}

		yamlContent, err := os.ReadFile(item.State.LocalPath)
		if err != nil {
			return fmt.Errorf("unable to read file %s: %w", item.State.LocalPath, err)
		}

		if err := yaml.Unmarshal(yamlContent, &appsecRule); err != nil {
			return fmt.Errorf("unable to parse yaml file %s: %w", item.State.LocalPath, err)
		}

		for _, ruleType := range appsec_rule.SupportedTypes() {
			fmt.Fprintf(os.Stdout, "\n%s format:\n", cases.Title(language.Und, cases.NoLower).String(ruleType))

			for _, rule := range appsecRule.Rules {
				convertedRule, _, err := rule.Convert(ruleType, appsecRule.Name, appsecRule.Description)
				if err != nil {
					return fmt.Errorf("unable to convert rule %s: %w", rule.Name, err)
				}

				fmt.Fprintln(os.Stdout, convertedRule)
			}

			switch ruleType { //nolint:gocritic
			case appsec_rule.ModsecurityRuleType:
				for _, rule := range appsecRule.SecLangRules {
					fmt.Fprintln(os.Stdout, rule)
				}
			}
		}

		return nil
	}

	return &cliItem{
		cfg:       cfg,
		name:      "appsec-rules",
		singular:  "appsec-rule",
		oneOrMore: "appsec-rule(s)",
		aliases:   []string{"waf-rules"},
		help: cliHelp{
			example: `cscli waf-rules list -a
cscli waf-rules install crowdsecurity/crs
cscli waf-rules inspect crowdsecurity/crs
cscli waf-rules upgrade crowdsecurity/crs
cscli waf-rules remove crowdsecurity/crs
`,
		},
		installHelp: cliHelp{
			example: `# Install some waf-rules.
cscli waf-rules install crowdsecurity/crs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli waf-rules install crowdsecurity/crs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli waf-rules install crowdsecurity/crs --dry-run -o raw

# Download only, to be installed later.
cscli waf-rules install crowdsecurity/crs --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli waf-rules install crowdsecurity/crs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli waf-rules install crowdsecurity/crs -i
cscli waf-rules install crowdsecurity/crs --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some waf-rules.
cscli waf-rules remove crowdsecurity/crs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli waf-rules remove crowdsecurity/crs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli waf-rules remove crowdsecurity/crs --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli waf-rules remove crowdsecurity/crs --purge

# Remove tainted items.
cscli waf-rules remove crowdsecurity/crs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli waf-rules remove crowdsecurity/crs -i
cscli waf-rules remove crowdsecurity/crs --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some waf-rules. If they are not currently installed, they are downloaded but not installed.
cscli waf-rules upgrade crowdsecurity/crs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli waf-rules upgrade crowdsecurity/crs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli waf-rules upgrade crowdsecurity/crs --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli waf-rules upgrade crowdsecurity/crs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli waf-rules upgrade crowdsecurity/crs -i
cscli waf-rules upgrade crowdsecurity/crs --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state, ancestor collections of waf-rules (installed or not).
cscli waf-rules inspect crowdsecurity/crs

# If the rule is installed, its metrics are collected and shown as well (with an error if crowdsec is not running).
# To avoid this, use --no-metrics.
cscli waf-rules inspect crowdsecurity/crs --no-metrics

# Display difference between a tainted item and the latest one.
cscli waf-rules inspect crowdsecurity/crs --diff

# Reverse the above diff
cscli waf-rules inspect crowdsecurity/crs --diff --rev`,
		},
		inspectDetail: inspectDetail,
		listHelp: cliHelp{
			example: `# List enabled (installed) waf-rules.
cscli waf-rules list

# List all available waf-rules (installed or not).
cscli waf-rules list -a

# List specific waf-rules (installed or not).
cscli waf-rules list crowdsecurity/crs crowdsecurity/vpatch-git-config`,
		},
	}
}
