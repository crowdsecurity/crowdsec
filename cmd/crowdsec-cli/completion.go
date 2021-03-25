package main

import (
	"os"

	"github.com/spf13/cobra"
)

func NewCompletionCmd() *cobra.Command {

	var completionCmd = &cobra.Command{
		Use:   "completion [bash|zsh]",
		Short: "Generate completion script",
		Long: `To load completions:

### Bash:

  $ source <(cscli completion bash)

  # To load completions for each session, execute once:


  # Linux:

  $ cscli completion bash | sudo tee /etc/bash_completion.d/cscli

  # macOS:

  $ cscli completion bash | sudo tee /usr/local/etc/bash_completion.d/cscli

### Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:

  $ cscli completion zsh > "${fpath[1]}/_cscli"

  # You will need to start a new shell for this setup to take effect.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh"},
		Args:                  cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
				/*case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
				*/
			}
		},
	}
	return completionCmd
}
