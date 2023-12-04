package appsec_rule

const (
	ModsecurityRuleType = "modsecurity"
)

func SupportedTypes() []string {
	return []string{ModsecurityRuleType}
}
