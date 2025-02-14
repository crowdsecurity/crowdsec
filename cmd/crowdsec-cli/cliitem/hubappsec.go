package cliitem

import (
	"fmt"
	"os"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewAppsecConfig(cfg configGetter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.APPSEC_CONFIGS,
		singular:  "appsec-config",
		oneOrMore: "appsec-config(s)",
		help: cliHelp{
			example: `cscli appsec-configs list -a
cscli appsec-configs install crowdsecurity/virtual-patching
cscli appsec-configs inspect crowdsecurity/virtual-patching
cscli appsec-configs upgrade crowdsecurity/virtual-patching
cscli appsec-configs remove crowdsecurity/virtual-patching
`,
		},
		installHelp: cliHelp{
			example: `# Install some appsec-configs.
cscli appsec-configs install crowdsecurity/virtual-patching

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli appsec-configs install crowdsecurity/virtual-patching --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli appsec-configs install crowdsecurity/virtual-patching --dry-run -o raw

# Download only, to be installed later.
cscli appsec-configs install crowdsecurity/virtual-patching --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli appsec-configs install crowdsecurity/virtual-patching --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli appsec-configs install crowdsecurity/virtual-patching -i
cscli appsec-configs install crowdsecurity/virtual-patching --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some appsec-configs.
cscli appsec-configs remove crowdsecurity/virtual-patching

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli appsec-configs remove crowdsecurity/virtual-patching --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli appsec-configs remove crowdsecurity/virtual-patching --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli appsec-configs remove crowdsecurity/virtual-patching --purge

# Remove tainted items.
cscli appsec-configs remove crowdsecurity/virtual-patching --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli appsec-configs remove crowdsecurity/virtual-patching -i
cscli appsec-configs remove crowdsecurity/virtual-patching --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some appsec-configs. If they are not currently installed, they are downloaded but not installed.
cscli appsec-configs upgrade crowdsecurity/virtual-patching

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli appsec-configs upgrade crowdsecurity/virtual-patching --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli appsec-configs upgrade crowdsecurity/virtual-patching --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli appsec-configs upgrade crowdsecurity/virtual-patching --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli appsec-configs upgrade crowdsecurity/virtual-patching -i
cscli appsec-configs upgrade crowdsecurity/virtual-patching --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state, metrics and ancestor collections of appsec-configs (installed or not).
cscli appsec-configs inspect crowdsecurity/virtual-patching

# Don't collect metrics (avoid error if crowdsec is not running).
cscli appsec-configs inspect crowdsecurity/virtual-patching --no-metrics

# Display difference between a tainted item and the latest one.
cscli appsec-configs inspect crowdsecurity/virtual-patching --diff

# Reverse the above diff
cscli appsec-configs inspect crowdsecurity/virtual-patching --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) appsec-configs.
cscli appsec-configs list

# List all available appsec-configs (installed or not).
cscli appsec-configs list -a

# List specific appsec-configs (installed or not).
cscli appsec-configs list crowdsecurity/virtual-patching crowdsecurity/generic-rules`,
		},
	}
}

func NewAppsecRule(cfg configGetter) *cliItem {
	inspectDetail := func(item *cwhub.Item) error {
		// Only show the converted rules in human mode
		if cfg().Cscli.Output != "human" {
			return nil
		}

		appsecRule := appsec.AppsecCollectionConfig{}

		yamlContent, err := os.ReadFile(item.State.LocalPath)
		if err != nil {
			return fmt.Errorf("unable to read file %s: %w", item.State.LocalPath, err)
		}

		if err := yaml.Unmarshal(yamlContent, &appsecRule); err != nil {
			return fmt.Errorf("unable to parse yaml file %s: %w", item.State.LocalPath, err)
		}

		for _, ruleType := range appsec_rule.SupportedTypes() {
			fmt.Printf("\n%s format:\n", cases.Title(language.Und, cases.NoLower).String(ruleType))

			for _, rule := range appsecRule.Rules {
				convertedRule, _, err := rule.Convert(ruleType, appsecRule.Name)
				if err != nil {
					return fmt.Errorf("unable to convert rule %s: %w", rule.Name, err)
				}

				fmt.Println(convertedRule)
			}

			switch ruleType { //nolint:gocritic
			case appsec_rule.ModsecurityRuleType:
				for _, rule := range appsecRule.SecLangRules {
					fmt.Println(rule)
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
		help: cliHelp{
			example: `cscli appsec-rules list -a
cscli appsec-rules install crowdsecurity/crs
cscli appsec-rules inspect crowdsecurity/crs
cscli appsec-rules upgrade crowdsecurity/crs
cscli appsec-rules remove crowdsecurity/crs
`,
		},
		installHelp: cliHelp{
			example: `# Install some appsec-rules.
cscli appsec-rules install crowdsecurity/crs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli appsec-rules install crowdsecurity/crs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli appsec-rules install crowdsecurity/crs --dry-run -o raw

# Download only, to be installed later.
cscli appsec-rules install crowdsecurity/crs --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli appsec-rules install crowdsecurity/crs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli appsec-rules install crowdsecurity/crs -i
cscli appsec-rules install crowdsecurity/crs --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some appsec-rules.
cscli appsec-rules remove crowdsecurity/crs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli appsec-rules remove crowdsecurity/crs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli appsec-rules remove crowdsecurity/crs --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli appsec-rules remove crowdsecurity/crs --purge

# Remove tainted items.
cscli appsec-rules remove crowdsecurity/crs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli appsec-rules remove crowdsecurity/crs -i
cscli appsec-rules remove crowdsecurity/crs --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some appsec-rules. If they are not currently installed, they are downloaded but not installed.
cscli appsec-rules upgrade crowdsecurity/crs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli appsec-rules upgrade crowdsecurity/crs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli appsec-rules upgrade crowdsecurity/crs --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli appsec-rules upgrade crowdsecurity/crs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli appsec-rules upgrade crowdsecurity/crs -i
cscli appsec-rules upgrade crowdsecurity/crs --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state, metrics and ancestor collections of appsec-rules (installed or not).
cscli appsec-rules inspect crowdsecurity/crs

# Don't collect metrics (avoid error if crowdsec is not running).
cscli appsec-configs inspect crowdsecurity/crs --no-metrics

# Display difference between a tainted item and the latest one.
cscli appsec-rules inspect crowdsecurity/crs --diff

# Reverse the above diff
cscli appsec-rules inspect crowdsecurity/crs --diff --rev`,
		},
		inspectDetail: inspectDetail,
		listHelp: cliHelp{
			example: `# List enabled (installed) appsec-rules.
cscli appsec-rules list

# List all available appsec-rules (installed or not).
cscli appsec-rules list -a

# List specific appsec-rules (installed or not).
cscli appsec-rules list crowdsecurity/crs crowdsecurity/vpatch-git-config`,
		},
	}
}
