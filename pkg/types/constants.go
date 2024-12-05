package types

const (
	ApiKeyAuthType   = "api-key"
	TlsAuthType      = "tls"
	PasswordAuthType = "password"
)

const (
	PAPIBaseURL        = "https://papi.api.crowdsec.net/"
	PAPIVersion        = "v1"
	PAPIPollUrl        = "/decisions/stream/poll"
	PAPIPermissionsUrl = "/permissions"
)

const CAPIBaseURL = "https://api.crowdsec.net/"

const (
	CscliOrigin                       = "cscli"
	CrowdSecOrigin                    = "crowdsec"
	ConsoleOrigin                     = "console"
	CscliImportOrigin                 = "cscli-import"
	ListOrigin                        = "lists"
	CAPIOrigin                        = "CAPI"
	CommunityBlocklistPullSourceScope = "crowdsecurity/community-blocklist"
)

const DecisionTypeBan = "ban"

func GetOrigins() []string {
	return []string{
		CscliOrigin,
		CrowdSecOrigin,
		ConsoleOrigin,
		CscliImportOrigin,
		ListOrigin,
		CAPIOrigin,
	}
}

// Leakybucket can be in mode LIVE or TIMEMACHINE
const (
	LIVE = iota
	TIMEMACHINE
)
