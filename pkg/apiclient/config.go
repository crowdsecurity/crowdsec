package apiclient

import (
	"net/url"

	"github.com/go-openapi/strfmt"
)

type Config struct {
	MachineID      string
	Password       strfmt.Password
	Scenarios      []string
	URL            *url.URL
	VersionPrefix  string
	UserAgent      string
	UpdateScenario func() ([]string, error)
}
