package appsec_rule

import (
	"fmt"
	"hash/fnv"
	"strings"
)

type ModsecurityRule struct {
	ids []uint32
}

var zonesMap map[string]string = map[string]string{
	"ARGS":            "ARGS_GET",
	"ARGS_NAMES":      "ARGS_GET_NAMES",
	"BODY_ARGS":       "ARGS_POST",
	"BODY_ARGS_NAMES": "ARGS_POST_NAMES",
	"HEADERS_NAMES":   "REQUEST_HEADERS_NAMES",
	"HEADERS":         "REQUEST_HEADERS",
	"METHOD":          "REQUEST_METHOD",
	"PROTOCOL":        "REQUEST_PROTOCOL",
	"URI":             "REQUEST_URI",
	"RAW_BODY":        "REQUEST_BODY",
	"FILENAMES":       "FILES",
}

var transformMap map[string]string = map[string]string{
	"lowercase": "t:lowercase",
	"uppercase": "t:uppercase",
	"b64decode": "t:base64Decode",
	"hexdecode": "t:hexDecode",
	"length":    "t:length",
}

var matchMap map[string]string = map[string]string{
	"regex":           "@rx",
	"equals":          "@streq",
	"startsWith":      "@beginsWith",
	"endsWith":        "@endsWith",
	"contains":        "@contains",
	"libinjectionSQL": "@detectSQLi",
	"libinjectionXSS": "@detectXSS",
	"gt":              "@gt",
	"lt":              "@lt",
	"gte":             "@ge",
	"lte":             "@le",
}

var bodyTypeMatch map[string]string = map[string]string{
	"json":       "JSON",
	"xml":        "XML",
	"multipart":  "MULTIPART",
	"urlencoded": "URLENCODED",
}

func (m *ModsecurityRule) Build(rule *CustomRule, appsecRuleName string) (string, []uint32, error) {

	rules, err := m.buildRules(rule, appsecRuleName, false, 0, 0)

	if err != nil {
		return "", nil, err
	}

	//We return the id of the first generated rule, as it's the interesting one in case of chain or skip
	return strings.Join(rules, "\n"), m.ids, nil
}

func (m *ModsecurityRule) generateRuleID(rule *CustomRule, appsecRuleName string, depth int) uint32 {
	h := fnv.New32a()
	h.Write([]byte(appsecRuleName))
	h.Write([]byte(rule.Match.Type))
	h.Write([]byte(rule.Match.Value))
	h.Write([]byte(fmt.Sprintf("%d", depth)))
	for _, zone := range rule.Zones {
		h.Write([]byte(zone))
	}
	for _, transform := range rule.Transform {
		h.Write([]byte(transform))
	}
	id := h.Sum32()
	m.ids = append(m.ids, id)
	return id
}

func (m *ModsecurityRule) buildRules(rule *CustomRule, appsecRuleName string, and bool, toSkip int, depth int) ([]string, error) {
	ret := make([]string, 0)

	if len(rule.And) != 0 && len(rule.Or) != 0 {
		return nil, fmt.Errorf("cannot have both 'and' and 'or' in the same rule")
	}

	if rule.And != nil {
		for c, andRule := range rule.And {
			depth++
			lastRule := c == len(rule.And)-1 // || len(rule.Or) == 0
			rules, err := m.buildRules(&andRule, appsecRuleName, !lastRule, 0, depth)
			if err != nil {
				return nil, err
			}
			ret = append(ret, rules...)
		}
	}

	if rule.Or != nil {
		for c, orRule := range rule.Or {
			depth++
			skip := len(rule.Or) - c - 1
			rules, err := m.buildRules(&orRule, appsecRuleName, false, skip, depth)
			if err != nil {
				return nil, err
			}
			ret = append(ret, rules...)
		}
	}

	r := strings.Builder{}

	r.WriteString("SecRule ")

	if rule.Zones == nil {
		return ret, nil
	}

	for idx, zone := range rule.Zones {
		mappedZone, ok := zonesMap[zone]
		if !ok {
			return nil, fmt.Errorf("unknown zone '%s'", zone)
		}
		if len(rule.Variables) == 0 {
			r.WriteString(mappedZone)
		} else {
			for j, variable := range rule.Variables {
				if idx > 0 || j > 0 {
					r.WriteByte('|')
				}
				r.WriteString(fmt.Sprintf("%s:%s", mappedZone, variable))
			}
		}
	}
	r.WriteByte(' ')

	if rule.Match.Type != "" {
		if match, ok := matchMap[rule.Match.Type]; ok {
			r.WriteString(fmt.Sprintf(`"%s %s"`, match, rule.Match.Value))
		} else {
			return nil, fmt.Errorf("unknown match type '%s'", rule.Match.Type)
		}
	}

	//Should phase:2 be configurable?
	r.WriteString(fmt.Sprintf(` "id:%d,phase:2,deny,log,msg:'%s',tag:'crowdsec-%s'`, m.generateRuleID(rule, appsecRuleName, depth), appsecRuleName, appsecRuleName))

	if rule.Transform != nil {
		for _, transform := range rule.Transform {
			r.WriteByte(',')
			if mappedTransform, ok := transformMap[transform]; ok {
				r.WriteString(mappedTransform)
			} else {
				return nil, fmt.Errorf("unknown transform '%s'", transform)
			}
		}
	}

	if rule.BodyType != "" {
		if mappedBodyType, ok := bodyTypeMatch[rule.BodyType]; ok {
			r.WriteString(fmt.Sprintf(",ctl:requestBodyProcessor=%s", mappedBodyType))
		} else {
			return nil, fmt.Errorf("unknown body type '%s'", rule.BodyType)
		}
	}

	if and {
		r.WriteString(",chain")
	}

	if toSkip > 0 {
		r.WriteString(fmt.Sprintf(",skip:%d", toSkip))
	}

	r.WriteByte('"')

	ret = append(ret, r.String())
	return ret, nil
}
