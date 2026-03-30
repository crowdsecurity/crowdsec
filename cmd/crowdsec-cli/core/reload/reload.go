package reload

import (
	"os"

	isatty "github.com/mattn/go-isatty"

	"github.com/crowdsecurity/go-cs-lib/version"
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
