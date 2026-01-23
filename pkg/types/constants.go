package types

const (
	ApiKeyAuthType   = "api-key"
	TlsAuthType      = "tls"
	PasswordAuthType = "password"
)

const (
	CscliOrigin                       = "cscli"
	CrowdSecOrigin                    = "crowdsec"
	ConsoleOrigin                     = "console"
	CscliImportOrigin                 = "cscli-import"
	ListOrigin                        = "lists"
	CAPIOrigin                        = "CAPI"
	CommunityBlocklistPullSourceScope = "crowdsecurity/community-blocklist"
	RemediationSyncOrigin             = "remediation_sync"
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
		RemediationSyncOrigin,
	}
}
