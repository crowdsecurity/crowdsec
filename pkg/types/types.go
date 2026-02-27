package types

import (
	"strings"
)

type AuthType = string

const (
	ApiKeyAuthType   AuthType = "api-key"
	TlsAuthType      AuthType = "tls"
	PasswordAuthType AuthType = "password"
)

type DecisionType = string

const (
	DecisionTypeBan DecisionType     = "ban"
	// TODO: add captcha, fix name..
)

type Origin = string

const (
	CscliOrigin Origin                       = "cscli"
	CrowdSecOrigin Origin                    = "crowdsec"
	ConsoleOrigin Origin                     = "console"
	CscliImportOrigin Origin                 = "cscli-import"
	ListOrigin Origin                        = "lists"
	CAPIOrigin Origin                        = "CAPI"
	CommunityBlocklistPullSourceScope Origin = "crowdsecurity/community-blocklist"
	RemediationSyncOrigin Origin             = "remediation_sync"
)

func GetOrigins() []Origin {
	return []Origin{
		CscliOrigin,
		CrowdSecOrigin,
		ConsoleOrigin,
		CscliImportOrigin,
		ListOrigin,
		CAPIOrigin,
		RemediationSyncOrigin,
	}
}

type Scope = string

// Move in leakybuckets
const (
	// TODO: fix names
	Undefined Scope = ""
	Ip        Scope = "Ip"
	Range     Scope = "Range"
	Filter    Scope = "Filter"
	Country   Scope = "Country"
	AS        Scope = "AS"
)

func NormalizeScope(strScope string) Scope {
	switch strings.ToLower(strScope) {
	case "ip":
		return Ip
	case "range":
		return Range
	case "as":
		return AS
	case "country":
		return Country
	default:
		return strScope
	}
}
