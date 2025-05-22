package apiclient

import (
	"context"
	"net/url"

	"github.com/go-openapi/strfmt"
)

const TokenDBField = "apic_token"

type Config struct {
	MachineID         string
	Password          strfmt.Password
	URL               *url.URL
	PapiURL           *url.URL
	VersionPrefix     string
	UserAgent         string
	RegistrationToken string
	UpdateScenario    func(context.Context) ([]string, error)
	TokenSave         func(context.Context, string, string) error
}
