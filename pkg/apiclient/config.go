package apiclient

import (
	"context"
	"net/url"

	"github.com/go-openapi/strfmt"
)

type Config struct {
	MachineID         string
	Password          strfmt.Password
	Scenarios         []string
	URL               *url.URL
	PapiURL           *url.URL
	VersionPrefix     string
	UserAgent         string
	RegistrationToken string
	UpdateScenario    func(context.Context) ([]string, error)
}
