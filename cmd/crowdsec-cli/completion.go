package main

import (
	"os"

	"github.com/spf13/cobra"
)

func NewCompletionCmd() *cobra.Command {

	var completionCmd = &cobra.Command{
		Use:   "completion [bash|zsh|powershell|fish]",
		Short: "Generate completion script",
		Long: `To load completions:

### Bash:
` + "```shell" + `
  $ source <(cscli completion bash)

  # To load completions for each session, execute once:


  # Linux:

  $ cscli completion bash | sudo tee /etc/bash_completion.d/cscli
  $ source ~/.bashrc

  # macOS:

  $ cscli completion bash | sudo tee /usr/local/etc/bash_completion.d/cscli

  # Troubleshoot:
  If you have this error (bash: _get_comp_words_by_ref: command not found), it seems that you need "bash-completion" dependency :

  * Install bash-completion package
  $ source /etc/profile
  $ source <(cscli completion bash)
` + "```" + `

### Zsh:
` + "```shell" + `
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:

  $ cscli completion zsh > "${fpath[1]}/_cscli"

  # You will need to start a new shell for this setup to take effect.

### fish:
` + "```shell" + `
  $ cscli completion fish | source

  # To load completions for each session, execute once:
  $ cscli completion fish > ~/.config/fish/completions/cscli.fish
` + "```" + `
### PowerShell:
` + "```powershell" + `
  PS> cscli completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> cscli completion powershell > cscli.ps1
  # and source this file from your PowerShell profile.
` + "```",
		DisableFlagsInUseLine: true,
		DisableAutoGenTag:     true,
		ValidArgs:             []string{"bash", "zsh", "powershell", "fish"},
		Args:                  cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "powershell":
				cmd.Root().GenPowerShellCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			}
		},
	}
	return completionCmd
}
