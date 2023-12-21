package main

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

func NewCLIAppsecConfig() *cliItem {
	return &cliItem{
		name:      cwhub.APPSEC_CONFIGS,
		singular:  "appsec-config",
		oneOrMore: "appsec-config(s)",
		help: cliHelp{
			example: `cscli appsec-configs list -a
cscli appsec-configs install crowdsecurity/vpatch
cscli appsec-configs inspect crowdsecurity/vpatch
cscli appsec-configs upgrade crowdsecurity/vpatch
cscli appsec-configs remove crowdsecurity/vpatch
`,
		},
		installHelp: cliHelp{
			example: `cscli appsec-configs install crowdsecurity/vpatch`,
		},
		removeHelp: cliHelp{
			example: `cscli appsec-configs remove crowdsecurity/vpatch`,
		},
		upgradeHelp: cliHelp{
			example: `cscli appsec-configs upgrade crowdsecurity/vpatch`,
		},
		inspectHelp: cliHelp{
			example: `cscli appsec-configs inspect crowdsecurity/vpatch`,
		},
		listHelp: cliHelp{
			example: `cscli appsec-configs list
cscli appsec-configs list -a
cscli appsec-configs list crowdsecurity/vpatch`,
		},
	}
}

func NewCLIAppsecRule() *cliItem {
	inspectDetail := func(item *cwhub.Item) error {
		//Only show the converted rules in human mode
		if csConfig.Cscli.Output != "human" {
			return nil
		}
		appsecRule := appsec.AppsecCollectionConfig{}

		yamlContent, err := os.ReadFile(item.State.LocalPath)
		if err != nil {
			return fmt.Errorf("unable to read file %s : %s", item.State.LocalPath, err)
		}

		if err := yaml.Unmarshal(yamlContent, &appsecRule); err != nil {
			return fmt.Errorf("unable to unmarshal yaml file %s : %s", item.State.LocalPath, err)
		}

		for _, ruleType := range appsec_rule.SupportedTypes() {
			fmt.Printf("\n%s format:\n", cases.Title(language.Und, cases.NoLower).String(ruleType))

			for _, rule := range appsecRule.Rules {
				convertedRule, _, err := rule.Convert(ruleType, appsecRule.Name)
				if err != nil {
					return fmt.Errorf("unable to convert rule %s : %s", rule.Name, err)
				}
				fmt.Println(convertedRule)
			}
		}

		return nil
	}

	return &cliItem{
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
			example: `cscli appsec-rules install crowdsecurity/crs`,
		},
		removeHelp: cliHelp{
			example: `cscli appsec-rules remove crowdsecurity/crs`,
		},
		upgradeHelp: cliHelp{
			example: `cscli appsec-rules upgrade crowdsecurity/crs`,
		},
		inspectHelp: cliHelp{
			example: `cscli appsec-rules inspect crowdsecurity/crs`,
		},
		inspectDetail: inspectDetail,
		listHelp: cliHelp{
			example: `cscli appsec-rules list
cscli appsec-rules list -a
cscli appsec-rules list crowdsecurity/crs`,
		},
	}
}
