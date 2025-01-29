package reload

import (
	"github.com/crowdsecurity/go-cs-lib/version"
)

func UserMessage() string {
	if version.System == "docker" {
		return ""
	}

	return message
}
