package types

import (
	"regexp"
	"slices"

	log "github.com/sirupsen/logrus"
)

/*
 1. If user triggered a rule that is for a CVE, that has high confidence and that is blocking, ban
 2. If user triggered 3 distinct rules with medium confidence across 3 different requests, ban


any(evt.Waf.ByTag("CVE"), {.confidence == "high" && .action == "block"})

len(evt.Waf.ByTagRx("*CVE*").ByConfidence("high").ByAction("block")) > 1

*/

type MatchedRules []map[string]interface{}

type AppsecEvent struct {
	HasInBandMatches, HasOutBandMatches bool
	MatchedRules
	Vars map[string]string
}
type Field string

func (f Field) String() string {
	return string(f)
}

const (
	ID         Field = "id"
	RuleType   Field = "rule_type"
	Tags       Field = "tags"
	File       Field = "file"
	Confidence Field = "confidence"
	Revision   Field = "revision"
	SecMark    Field = "secmark"
	Accuracy   Field = "accuracy"
	Msg        Field = "msg"
	Severity   Field = "severity"
	Kind       Field = "kind"
)

func (w AppsecEvent) GetVar(varName string) string {
	if w.Vars == nil {
		return ""
	}
	if val, ok := w.Vars[varName]; ok {
		return val
	}
	log.Infof("var %s not found. Available variables: %+v", varName, w.Vars)
	return ""

}

// getters
func (w MatchedRules) GetField(field Field) []interface{} {
	ret := make([]interface{}, 0)
	for _, rule := range w {
		ret = append(ret, rule[field.String()])
	}
	return ret
}

func (w MatchedRules) GetURI() string {
	for _, rule := range w {
		return rule["uri"].(string)
	}
	return ""
}

func (w MatchedRules) GetHash() string {
	for _, rule := range w {
		//@sbl : let's fix this
		return rule["hash"].(string)
	}
	return ""
}

func (w MatchedRules) GetVersion() string {
	for _, rule := range w {
		//@sbl : let's fix this
		return rule["version"].(string)
	}
	return ""
}

func (w MatchedRules) GetName() string {
	for _, rule := range w {
		//@sbl : let's fix this
		return rule["name"].(string)
	}
	return ""
}

func (w MatchedRules) GetMethod() string {
	for _, rule := range w {
		return rule["method"].(string)
	}
	return ""
}

func (w MatchedRules) GetRuleIDs() []int {
	ret := make([]int, 0)
	for _, rule := range w {
		ret = append(ret, rule["id"].(int))
	}
	return ret
}

func (w MatchedRules) Kinds() []string {
	ret := make([]string, 0)
	for _, rule := range w {
		exists := false
		for _, val := range ret {
			if val == rule["kind"] {
				exists = true
				break
			}
		}
		if !exists {
			ret = append(ret, rule["kind"].(string))
		}
	}
	return ret
}

func (w MatchedRules) GetMatchedZones() []string {
	ret := make([]string, 0)

	for _, rule := range w {
		for _, zone := range rule["matched_zones"].([]string) {
			if !slices.Contains(ret, zone) {
				ret = append(ret, zone)
			}
		}
	}
	return ret
}

// filters
func (w MatchedRules) ByID(id int) MatchedRules {
	ret := MatchedRules{}

	for _, rule := range w {
		if rule["id"] == id {
			ret = append(ret, rule)
		}
	}
	return ret
}

func (w MatchedRules) ByKind(kind string) MatchedRules {
	ret := MatchedRules{}
	for _, rule := range w {
		if rule["kind"] == kind {
			ret = append(ret, rule)
		}
	}
	return ret
}

func (w MatchedRules) ByTags(match []string) MatchedRules {
	ret := MatchedRules{}
	for _, rule := range w {
		for _, tag := range rule["tags"].([]string) {
			for _, match_tag := range match {
				if tag == match_tag {
					ret = append(ret, rule)
					break
				}
			}
		}
	}
	return ret
}

func (w MatchedRules) ByTag(match string) MatchedRules {
	ret := MatchedRules{}
	for _, rule := range w {
		for _, tag := range rule["tags"].([]string) {
			if tag == match {
				ret = append(ret, rule)
				break
			}
		}
	}
	return ret
}

func (w MatchedRules) ByTagRx(rx string) MatchedRules {
	ret := MatchedRules{}
	re := regexp.MustCompile(rx)
	if re == nil {
		return ret
	}
	for _, rule := range w {
		for _, tag := range rule["tags"].([]string) {
			log.Debugf("ByTagRx: %s = %s -> %t", rx, tag, re.MatchString(tag))
			if re.MatchString(tag) {
				ret = append(ret, rule)
				break
			}
		}
	}
	return ret
}

func (w MatchedRules) ByDisruptiveness(is bool) MatchedRules {
	ret := MatchedRules{}
	for _, rule := range w {
		if rule["disruptive"] == is {
			ret = append(ret, rule)
		}
	}
	log.Debugf("ByDisruptiveness(%t) -> %d", is, len(ret))

	return ret
}

func (w MatchedRules) BySeverity(severity string) MatchedRules {
	ret := MatchedRules{}
	for _, rule := range w {
		if rule["severity"] == severity {
			ret = append(ret, rule)
		}
	}
	log.Debugf("BySeverity(%s) -> %d", severity, len(ret))
	return ret
}

func (w MatchedRules) ByAccuracy(accuracy string) MatchedRules {
	ret := MatchedRules{}
	for _, rule := range w {
		if rule["accuracy"] == accuracy {
			ret = append(ret, rule)
		}
	}
	log.Debugf("ByAccuracy(%s) -> %d", accuracy, len(ret))
	return ret
}
