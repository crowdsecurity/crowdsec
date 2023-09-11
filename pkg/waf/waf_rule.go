package waf

type VPatchRule struct {
	//Those 2 together represent something like ARGS.foo
	//If only target is set, it's used for variables that are not a collection (REQUEST_METHOD, etc)
	Target   string `yaml:"target"`
	Variable string `yaml:"var"`

	//Operations
	Match     string `yaml:"match"`     //@rx
	Equals    string `yaml:"equals"`    //@eq
	Transform string `yaml:"transform"` //t:lowercase, t:uppercase, etc
	Detect    string `yaml:"detect"`    //@detectXSS, @detectSQLi, etc

	RulesOr  []VPatchRule `yaml:"rules_or"`
	RulesAnd []VPatchRule `yaml:"rules_and"`
}

func (v *VPatchRule) String() string {
	//ret := "SecRule "

	if v.Target != "" {
	}
	return ""
}
