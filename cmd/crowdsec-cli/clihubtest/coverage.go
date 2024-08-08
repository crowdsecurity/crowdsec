package clihubtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func (cli *cliHubTest) coverage(showScenarioCov bool, showParserCov bool, showAppsecCov bool, showOnlyPercent bool) error {
	cfg := cli.cfg()

	// for this one we explicitly don't do for appsec
	if err := HubTest.LoadAllTests(); err != nil {
		return fmt.Errorf("unable to load all tests: %+v", err)
	}

	var err error

	scenarioCoverage := []hubtest.Coverage{}
	parserCoverage := []hubtest.Coverage{}
	appsecRuleCoverage := []hubtest.Coverage{}
	scenarioCoveragePercent := 0
	parserCoveragePercent := 0
	appsecRuleCoveragePercent := 0

	// if both are false (flag by default), show both
	showAll := !showScenarioCov && !showParserCov && !showAppsecCov

	if showParserCov || showAll {
		parserCoverage, err = HubTest.GetParsersCoverage()
		if err != nil {
			return fmt.Errorf("while getting parser coverage: %w", err)
		}

		parserTested := 0

		for _, test := range parserCoverage {
			if test.TestsCount > 0 {
				parserTested++
			}
		}

		parserCoveragePercent = int(math.Round((float64(parserTested) / float64(len(parserCoverage)) * 100)))
	}

	if showScenarioCov || showAll {
		scenarioCoverage, err = HubTest.GetScenariosCoverage()
		if err != nil {
			return fmt.Errorf("while getting scenario coverage: %w", err)
		}

		scenarioTested := 0

		for _, test := range scenarioCoverage {
			if test.TestsCount > 0 {
				scenarioTested++
			}
		}

		scenarioCoveragePercent = int(math.Round((float64(scenarioTested) / float64(len(scenarioCoverage)) * 100)))
	}

	if showAppsecCov || showAll {
		appsecRuleCoverage, err = HubTest.GetAppsecCoverage()
		if err != nil {
			return fmt.Errorf("while getting scenario coverage: %w", err)
		}

		appsecRuleTested := 0

		for _, test := range appsecRuleCoverage {
			if test.TestsCount > 0 {
				appsecRuleTested++
			}
		}

		appsecRuleCoveragePercent = int(math.Round((float64(appsecRuleTested) / float64(len(appsecRuleCoverage)) * 100)))
	}

	if showOnlyPercent {
		switch {
		case showAll:
			fmt.Printf("parsers=%d%%\nscenarios=%d%%\nappsec_rules=%d%%", parserCoveragePercent, scenarioCoveragePercent, appsecRuleCoveragePercent)
		case showParserCov:
			fmt.Printf("parsers=%d%%", parserCoveragePercent)
		case showScenarioCov:
			fmt.Printf("scenarios=%d%%", scenarioCoveragePercent)
		case showAppsecCov:
			fmt.Printf("appsec_rules=%d%%", appsecRuleCoveragePercent)
		}

		return nil
	}

	switch cfg.Cscli.Output {
	case "human":
		if showParserCov || showAll {
			hubTestParserCoverageTable(color.Output, cfg.Cscli.Color, parserCoverage)
		}

		if showScenarioCov || showAll {
			hubTestScenarioCoverageTable(color.Output, cfg.Cscli.Color, scenarioCoverage)
		}

		if showAppsecCov || showAll {
			hubTestAppsecRuleCoverageTable(color.Output, cfg.Cscli.Color, appsecRuleCoverage)
		}

		fmt.Println()

		if showParserCov || showAll {
			fmt.Printf("PARSERS    : %d%% of coverage\n", parserCoveragePercent)
		}

		if showScenarioCov || showAll {
			fmt.Printf("SCENARIOS  : %d%% of coverage\n", scenarioCoveragePercent)
		}

		if showAppsecCov || showAll {
			fmt.Printf("APPSEC RULES  : %d%% of coverage\n", appsecRuleCoveragePercent)
		}
	case "json":
		dump, err := json.MarshalIndent(parserCoverage, "", " ")
		if err != nil {
			return err
		}

		fmt.Printf("%s", dump)

		dump, err = json.MarshalIndent(scenarioCoverage, "", " ")
		if err != nil {
			return err
		}

		fmt.Printf("%s", dump)

		dump, err = json.MarshalIndent(appsecRuleCoverage, "", " ")
		if err != nil {
			return err
		}

		fmt.Printf("%s", dump)
	default:
		return errors.New("only human/json output modes are supported")
	}

	return nil
}

func (cli *cliHubTest) NewCoverageCmd() *cobra.Command {
	var (
		showParserCov   bool
		showScenarioCov bool
		showOnlyPercent bool
		showAppsecCov   bool
	)

	cmd := &cobra.Command{
		Use:               "coverage",
		Short:             "coverage",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.coverage(showScenarioCov, showParserCov, showAppsecCov, showOnlyPercent)
		},
	}

	cmd.PersistentFlags().BoolVar(&showOnlyPercent, "percent", false, "Show only percentages of coverage")
	cmd.PersistentFlags().BoolVar(&showParserCov, "parsers", false, "Show only parsers coverage")
	cmd.PersistentFlags().BoolVar(&showScenarioCov, "scenarios", false, "Show only scenarios coverage")
	cmd.PersistentFlags().BoolVar(&showAppsecCov, "appsec", false, "Show only appsec coverage")

	return cmd
}
