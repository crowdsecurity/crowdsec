package waap_rule

const (
	ModsecurityRuleType = "modsecurity"
)

func SupportedTypes() []string {
	return []string{ModsecurityRuleType}
}
