package models

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

const (
	// these are duplicated from pkg/types
	// TODO XXX: de-duplicate
	Ip                = "Ip"
	Range             = "Range"
	CscliImportOrigin = "cscli-import"
)

func (a *Alert) GetScope() string {
	return a.Source.GetScope()
}

func (a *Alert) GetValue() string {
	return a.Source.GetValue()
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

func (a *Alert) GetMeta(key string) string {
	for _, meta := range a.Meta {
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

func (s Source) GetAsNumberName() string {
	ret := ""
	if s.AsNumber != "0" {
		ret += s.AsNumber
	}

	if s.AsName != "" {
		ret += " " + s.AsName
	}

	return ret
}

func (s *Source) String() string {
	if s == nil || s.Scope == nil || *s.Scope == "" {
		return "empty source"
	}

	cn := s.Cn

	if s.AsNumber != "" {
		cn += "/" + s.AsNumber
	}

	if cn != "" {
		cn = " (" + cn + ")"
	}

	switch *s.Scope {
	case Ip:
		return "ip " + *s.Value + cn
	case Range:
		return "range " + *s.Value + cn
	default:
		return *s.Scope + " " + *s.Value
	}
}

func (a *Alert) FormatAsStrings(machineID string, logger *log.Logger) []string {
	src := a.Source.String()

	msg := "empty scenario"
	if a.Scenario != nil && *a.Scenario != "" {
		msg = *a.Scenario
	} else if a.Message != nil && *a.Message != "" {
		msg = *a.Message
	}

	reason := fmt.Sprintf("%s by %s", msg, src)

	if len(a.Decisions) == 0 {
		return []string{fmt.Sprintf("(%s) alert : %s", machineID, reason)}
	}

	var retStr []string

	if a.Decisions[0].Origin != nil && *a.Decisions[0].Origin == CscliImportOrigin {
		return []string{fmt.Sprintf("(%s) alert : %s", machineID, reason)}
	}

	for i, decisionItem := range a.Decisions {
		decision := ""
		if a.Simulated != nil && *a.Simulated {
			decision = "(simulated alert)"
		} else if decisionItem.Simulated != nil && *decisionItem.Simulated {
			decision = "(simulated decision)"
		}

		if logger.IsLevelEnabled(log.DebugLevel) {
			logger.Debug(spew.Sdump(decisionItem))
		}

		if len(a.Decisions) > 1 {
			reason = fmt.Sprintf("%s for %d/%d decisions", msg, i+1, len(a.Decisions))
		}

		origin := *decisionItem.Origin
		if machineID != "" {
			origin = machineID + "/" + origin
		}

		decision += fmt.Sprintf("%s %s on %s %s", *decisionItem.Duration,
			*decisionItem.Type, *decisionItem.Scope, *decisionItem.Value)
		retStr = append(retStr,
			fmt.Sprintf("(%s) %s : %s", origin, reason, decision))
	}

	return retStr
}
