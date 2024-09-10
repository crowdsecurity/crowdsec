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

// getCoverage returns the coverage and the percentage of tests that passed
func getCoverage(show bool, getCoverageFunc func() ([]hubtest.Coverage, error)) ([]hubtest.Coverage, int, error) {
	if !show {
		return nil, 0, nil
	}

	coverage, err := getCoverageFunc()
	if err != nil {
		return nil, 0, fmt.Errorf("while getting coverage: %w", err)
	}

	tested := 0

	for _, test := range coverage {
		if test.TestsCount > 0 {
			tested++
		}
	}

	// keep coverage 0 if there's no tests?
	percent := 0
	if len(coverage) > 0 {
		percent = int(math.Round((float64(tested) / float64(len(coverage)) * 100)))
	}

	return coverage, percent, nil
}

func (cli *cliHubTest) coverage(showScenarioCov bool, showParserCov bool, showAppsecCov bool, showOnlyPercent bool) error {
	cfg := cli.cfg()

	// for this one we explicitly don't do for appsec
	if err := HubTest.LoadAllTests(); err != nil {
		return fmt.Errorf("unable to load all tests: %+v", err)
	}

	var err error

	// if all are false (flag by default), show them
	if !showParserCov && !showScenarioCov && !showAppsecCov {
		showParserCov = true
		showScenarioCov = true
		showAppsecCov = true
	}

	parserCoverage, parserCoveragePercent, err := getCoverage(showParserCov, HubTest.GetParsersCoverage)
	if err != nil {
		return err
	}

	scenarioCoverage, scenarioCoveragePercent, err := getCoverage(showScenarioCov, HubTest.GetScenariosCoverage)
	if err != nil {
		return err
	}

	appsecRuleCoverage, appsecRuleCoveragePercent, err := getCoverage(showAppsecCov, HubTest.GetAppsecCoverage)
	if err != nil {
		return err
	}

	if showOnlyPercent {
		switch {
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
		if showParserCov {
			hubTestCoverageTable(color.Output, cfg.Cscli.Color, []string{"Parser", "Status", "Number of tests"}, parserCoverage)
		}

		if showScenarioCov {
			hubTestCoverageTable(color.Output, cfg.Cscli.Color, []string{"Scenario", "Status", "Number of tests"}, parserCoverage)
		}

		if showAppsecCov {
			hubTestCoverageTable(color.Output, cfg.Cscli.Color, []string{"Appsec Rule", "Status", "Number of tests"}, parserCoverage)
		}

		fmt.Println()

		if showParserCov {
			fmt.Printf("PARSERS    : %d%% of coverage\n", parserCoveragePercent)
		}

		if showScenarioCov {
			fmt.Printf("SCENARIOS  : %d%% of coverage\n", scenarioCoveragePercent)
		}

		if showAppsecCov {
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

func (cli *cliHubTest) newCoverageCmd() *cobra.Command {
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
