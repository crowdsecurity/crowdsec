package types

const ApiKeyAuthType = "api-key"
const TlsAuthType = "tls"
const PasswordAuthType = "password"

const PAPIBaseURL = "https://papi.api.crowdsec.net/"
const PAPIVersion = "v1"
const PAPIPollUrl = "/decisions/stream/poll"
const PAPIPermissionsUrl = "/permissions"

const CAPIBaseURL = "https://api.crowdsec.net/"

const CscliOrigin = "cscli"
const CrowdSecOrigin = "crowdsec"
const ConsoleOrigin = "console"
const CscliImportOrigin = "cscli-import"
const ListOrigin = "lists"
const CAPIOrigin = "CAPI"

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
