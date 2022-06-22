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

func (a *Alert) GetValue() string {
	if a.Source.Value == nil {
		return ""
	}
	return *a.Source.Value
}

func (a *Alert) GetScenario() string {
	if a.Scenario == nil {
		return ""
	}
	return *a.Scenario
}

func (a *Alert) GetEventsCount() int32 {
	if a.EventsCount == nil {
		return 0
	}
	return *a.EventsCount
}

func (e *Event) GetMeta(key string) string {
	for _, meta := range e.Meta {
		if meta.Key == key {
			return meta.Value
		}
	}
	return ""
}

func (s Source) GetValue() string {
	if s.Value == nil {
		return ""
	}
	return *s.Value
}

func (s Source) GetScope() string {
	if s.Scope == nil {
		return ""
	}
	return *s.Scope
}
