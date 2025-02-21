package reload

import (
	"os"

	"github.com/crowdsecurity/go-cs-lib/version"
	isatty "github.com/mattn/go-isatty"
)

func UserMessage() string {
	if version.System == "docker" {
		if isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()) {
			return "You may need to restart the container to apply the changes."
		}

		return ""
	}

	return message
}
