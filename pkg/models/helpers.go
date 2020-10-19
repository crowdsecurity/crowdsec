package models

func (a *Alert) HasRemediation() bool {
	return true
}

func (a *Alert) Scope() string {
	if a.Source.Scope == nil {
		return ""
	}
	return *a.Source.Scope
}
