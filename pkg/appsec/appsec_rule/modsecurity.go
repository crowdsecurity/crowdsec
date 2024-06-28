package appsec_rule

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
)

type ModsecurityRule struct {
	ids []uint32
}

var zonesMap = map[string]string{
	"ARGS":             "ARGS_GET",
	"ARGS_NAMES":       "ARGS_GET_NAMES",
	"BODY_ARGS":        "ARGS_POST",
	"BODY_ARGS_NAMES":  "ARGS_POST_NAMES",
	"COOKIES":          "REQUEST_COOKIES",
	"COOKIES_NAMES":    "REQUEST_COOKIES_NAMES",
	"FILES":            "FILES",
	"FILES_NAMES":      "FILES_NAMES",
	"FILES_TOTAL_SIZE": "FILES_COMBINED_SIZE",
	"HEADERS_NAMES":    "REQUEST_HEADERS_NAMES",
	"HEADERS":          "REQUEST_HEADERS",
	"METHOD":           "REQUEST_METHOD",
	"PROTOCOL":         "REQUEST_PROTOCOL",
	"URI":              "REQUEST_FILENAME",
	"URI_FULL":         "REQUEST_URI",
	"RAW_BODY":         "REQUEST_BODY",
	"FILENAMES":        "FILES",
}

var transformMap = map[string]string{
	"lowercase": "t:lowercase",
	"uppercase": "t:uppercase",
	"b64decode": "t:base64Decode",
	//"hexdecode":          "t:hexDecode", -> not supported by coraza
	"length":             "t:length",
	"urldecode":          "t:urlDecode",
	"trim":               "t:trim",
	"normalize_path":     "t:normalizePath",
	"normalizepath":      "t:normalizePath",
	"htmlentitydecode":   "t:htmlEntityDecode",
	"html_entity_decode": "t:htmlEntityDecode",
}

var matchMap = map[string]string{
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
	"eq":              "@eq",
}

var bodyTypeMatch = map[string]string{
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
		return nil, errors.New("cannot have both 'and' and 'or' in the same rule")
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

	zone_prefix := ""
	variable_prefix := ""
	if rule.Transform != nil {
		for tidx, transform := range rule.Transform {
			if transform == "count" {
				zone_prefix = "&"
				rule.Transform[tidx] = ""
			}
		}
	}
	for idx, zone := range rule.Zones {
		if idx > 0 {
			r.WriteByte('|')
		}
		mappedZone, ok := zonesMap[zone]
		if !ok {
			return nil, fmt.Errorf("unknown zone '%s'", zone)
		}
		if len(rule.Variables) == 0 {
			r.WriteString(mappedZone)
		} else {
			for j, variable := range rule.Variables {
				if j > 0 {
					r.WriteByte('|')
				}
				r.WriteString(fmt.Sprintf("%s%s:%s%s", zone_prefix, mappedZone, variable_prefix, variable))
			}
		}
	}
	r.WriteByte(' ')

	if rule.Match.Type != "" {
		match, ok := matchMap[rule.Match.Type]
		if !ok {
			return nil, fmt.Errorf("unknown match type '%s'", rule.Match.Type)
		}
		prefix := ""
		if rule.Match.Not {
			prefix = "!"
		}
		r.WriteString(fmt.Sprintf(`"%s%s %s"`, prefix, match, rule.Match.Value))
	}

	//Should phase:2 be configurable?
	r.WriteString(fmt.Sprintf(` "id:%d,phase:2,deny,log,msg:'%s',tag:'crowdsec-%s'`, m.generateRuleID(rule, appsecRuleName, depth), appsecRuleName, appsecRuleName))

	if rule.Transform != nil {
		for _, transform := range rule.Transform {
			if transform == "" {
				continue
			}
			r.WriteByte(',')
			mappedTransform, ok := transformMap[transform]
			if !ok {
				return nil, fmt.Errorf("unknown transform '%s'", transform)
			}
			r.WriteString(mappedTransform)
		}
	}

	if rule.BodyType != "" {
		mappedBodyType, ok := bodyTypeMatch[rule.BodyType]
		if !ok {
			return nil, fmt.Errorf("unknown body type '%s'", rule.BodyType)
		}
		r.WriteString(fmt.Sprintf(",ctl:requestBodyProcessor=%s", mappedBodyType))
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
