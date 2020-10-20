package models

func (a *Alert) HasRemediation() bool {
	return true
}

func (a *Alert) GetScope() string {
	if a.Source.Scope == nil {
		return ""
	}
	return *a.Source.Scope
}

func (a *Alert) GetScenario() string {
	if a.Scenario == nil {
		return ""
	}
	return *a.Scenario
}
