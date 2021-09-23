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

func (e *Event) GetMeta(key string) string {
	for _, meta := range e.Meta {
		if meta.Key == key {
			return meta.Value
		}
	}
	return ""
}
