package clihubtest

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

type configGetter func() *csconfig.Config

var (
	HubTest        hubtest.HubTest
	HubAppsecTests hubtest.HubTest
	hubPtr         *hubtest.HubTest
	isAppsecTest   bool
)

type cliHubTest struct {
	cfg configGetter
}

func New(cfg configGetter) *cliHubTest {
	return &cliHubTest{
		cfg: cfg,
	}
}

func (cli *cliHubTest) NewCommand() *cobra.Command {
	var (
		hubPath      string
		crowdsecPath string
		cscliPath    string
	)

	cmd := &cobra.Command{
		Use:               "hubtest",
		Short:             "Run functional tests on hub configurations",
		Long:              "Run functional tests on hub configurations (parsers, scenarios, collections...)",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			var err error
			HubTest, err = hubtest.NewHubTest(hubPath, crowdsecPath, cscliPath, false)
			if err != nil {
				return fmt.Errorf("unable to load hubtest: %+v", err)
			}

			HubAppsecTests, err = hubtest.NewHubTest(hubPath, crowdsecPath, cscliPath, true)
			if err != nil {
				return fmt.Errorf("unable to load appsec specific hubtest: %+v", err)
			}

			// commands will use the hubPtr, will point to the default hubTest object, or the one dedicated to appsec tests
			hubPtr = &HubTest
			if isAppsecTest {
				hubPtr = &HubAppsecTests
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&hubPath, "hub", ".", "Path to hub folder")
	cmd.PersistentFlags().StringVar(&crowdsecPath, "crowdsec", "crowdsec", "Path to crowdsec")
	cmd.PersistentFlags().StringVar(&cscliPath, "cscli", "cscli", "Path to cscli")
	cmd.PersistentFlags().BoolVar(&isAppsecTest, "appsec", false, "Command relates to appsec tests")

	cmd.AddCommand(cli.newCreateCmd())
	cmd.AddCommand(cli.newRunCmd())
	cmd.AddCommand(cli.newCleanCmd())
	cmd.AddCommand(cli.newInfoCmd())
	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newCoverageCmd())
	cmd.AddCommand(cli.newEvalCmd())
	cmd.AddCommand(cli.newExplainCmd())

	return cmd
}
