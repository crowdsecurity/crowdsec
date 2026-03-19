package appsec_rule

import (
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"

	cztypes "github.com/corazawaf/coraza/v3/types"
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
	"RAW_BODY":         "RAW_REQUEST_BODY",
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
	"fromFile":        "@pmFromFile",
}

var bodyTypeMatch = map[string]string{
	"json":       "JSON",
	"xml":        "XML",
	"multipart":  "MULTIPART",
	"urlencoded": "URLENCODED",
}

const maxDNFGroups = 50

func (m *ModsecurityRule) Build(rule *CustomRule, appsecRuleName string, appsecRuleDescription string) (string, []uint32, error) {
	if rule.Severity == "" {
		rule.Severity = cztypes.RuleSeverityEmergency.String()
	}

	_, err := cztypes.ParseRuleSeverity(rule.Severity)
	if err != nil {
		return "", nil, err
	}

	dnf, err := flattenToDNF(rule)
	if err != nil {
		return "", nil, err
	}

	rules, err := m.buildFromDNF(dnf, rule.Severity, appsecRuleName, appsecRuleDescription)
	if err != nil {
		return "", nil, err
	}

	return strings.Join(rules, "\n"), m.ids, nil
}

// leafCopy returns a shallow copy of the rule with And/Or cleared.
func leafCopy(rule *CustomRule) *CustomRule {
	cp := *rule
	cp.And = nil
	cp.Or = nil

	return &cp
}

// flattenToDNF converts a CustomRule tree into Disjunctive Normal Form:
// a list of AND-groups (conjunctions), where the outer list is OR.
func flattenToDNF(rule *CustomRule) ([][]*CustomRule, error) {
	// Leaf node: has zones, no children
	if len(rule.And) == 0 && len(rule.Or) == 0 {
		if rule.Zones == nil {
			return nil, errors.New("leaf rule must have zones")
		}

		return [][]*CustomRule{{rule}}, nil
	}

	// Collect DNF parts to be AND-combined via cross-product
	var parts [][][]*CustomRule

	// If this node has zones alongside And/Or children, treat as implicit AND term
	if rule.Zones != nil {
		parts = append(parts, [][]*CustomRule{{leafCopy(rule)}})
	}

	// Each And child's DNF is cross-producted
	for i := range rule.And {
		childDNF, err := flattenToDNF(&rule.And[i])
		if err != nil {
			return nil, err
		}

		parts = append(parts, childDNF)
	}

	// All Or children's DNFs are concatenated into one, then treated as a single AND term
	if len(rule.Or) > 0 {
		var orDNF [][]*CustomRule

		for i := range rule.Or {
			childDNF, err := flattenToDNF(&rule.Or[i])
			if err != nil {
				return nil, err
			}

			orDNF = append(orDNF, childDNF...)
		}

		parts = append(parts, orDNF)
	}

	if len(parts) == 0 {
		return nil, errors.New("rule has no zones, 'and', or 'or' children")
	}

	if len(parts) == 1 {
		return parts[0], nil
	}

	// Multiple parts: cross-product them all
	result := parts[0]

	for i := 1; i < len(parts); i++ {
		var err error

		result, err = crossProduct(result, parts[i])
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// crossProduct computes the AND-combination of two DNFs.
// [[A],[B]] × [[C],[D]] = [[A,C],[A,D],[B,C],[B,D]]
func crossProduct(a, b [][]*CustomRule) ([][]*CustomRule, error) {
	result := make([][]*CustomRule, 0, len(a)*len(b))

	for _, groupA := range a {
		for _, groupB := range b {
			combined := make([]*CustomRule, 0, len(groupA)+len(groupB))
			combined = append(combined, groupA...)
			combined = append(combined, groupB...)
			result = append(result, combined)
		}
	}

	if len(result) > maxDNFGroups {
		return nil, fmt.Errorf("rule expansion produced %d groups, exceeding maximum of %d", len(result), maxDNFGroups)
	}

	return result, nil
}

func (m *ModsecurityRule) generateRuleID(rule *CustomRule, appsecRuleName string, position int) uint32 {
	h := fnv.New32a()
	h.Write([]byte(appsecRuleName))
	h.Write([]byte(rule.Match.Type))
	h.Write([]byte(rule.Match.Value))
	h.Write([]byte(fmt.Sprintf("%d", position)))

	for _, zone := range rule.Zones {
		h.Write([]byte(zone))
	}

	for _, transform := range rule.Transform {
		if transform == "count" {
			continue
		}

		h.Write([]byte(transform))
	}

	id := h.Sum32()
	m.ids = append(m.ids, id)

	return id
}

// buildFromDNF generates ModSecurity SecRule directives from DNF groups.
// Rules within each AND-group get ,chain (except the last).
// Last rule of each group (except the final group) gets ,skip:N.
func (m *ModsecurityRule) buildFromDNF(dnf [][]*CustomRule, severity string, appsecRuleName string, appsecRuleDescription string) ([]string, error) {
	groupSizes := make([]int, len(dnf))
	for i, group := range dnf {
		groupSizes[i] = len(group)
	}

	var rules []string

	position := 0

	for groupIdx, group := range dnf {
		for leafIdx, leaf := range group {
			isLastInGroup := leafIdx == len(group)-1
			isLastGroup := groupIdx == len(dnf)-1

			chain := !isLastInGroup

			skip := 0
			if isLastInGroup && !isLastGroup {
				for k := groupIdx + 1; k < len(dnf); k++ {
					skip += groupSizes[k]
				}
			}

			isRoot := position == 0

			ruleStr, err := m.buildSingleRule(leaf, severity, appsecRuleName, appsecRuleDescription, chain, skip, position, isRoot)
			if err != nil {
				return nil, err
			}

			rules = append(rules, ruleStr)
			position++
		}
	}

	return rules, nil
}

// buildSingleRule renders a single leaf CustomRule as a ModSecurity SecRule string.
func (m *ModsecurityRule) buildSingleRule(rule *CustomRule, severity string, appsecRuleName string, appsecRuleDescription string, chain bool, skip int, position int, isRoot bool) (string, error) {
	r := strings.Builder{}

	r.WriteString("SecRule ")

	zonePrefix := ""
	variablePrefix := ""

	hasCount := slices.Contains(rule.Transform, "count")
	if hasCount {
		zonePrefix = "&"
	}

	for idx, zone := range rule.Zones {
		if idx > 0 {
			r.WriteByte('|')
		}

		mappedZone, ok := zonesMap[zone]
		if !ok {
			return "", fmt.Errorf("unknown zone '%s'", zone)
		}

		if len(rule.Variables) == 0 {
			r.WriteString(mappedZone)
		} else {
			for j, variable := range rule.Variables {
				if j > 0 {
					r.WriteByte('|')
				}

				r.WriteString(fmt.Sprintf("%s%s:%s%s", zonePrefix, mappedZone, variablePrefix, variable))
			}
		}
	}

	r.WriteByte(' ')

	if rule.Match.Type != "" {
		match, ok := matchMap[rule.Match.Type]
		if !ok {
			return "", fmt.Errorf("unknown match type '%s'", rule.Match.Type)
		}

		prefix := ""
		if rule.Match.Not {
			prefix = "!"
		}

		r.WriteString(fmt.Sprintf(`"%s%s %s"`, prefix, match, rule.Match.Value))
	}

	var msg string
	if appsecRuleDescription != "" {
		msg = appsecRuleDescription
	} else {
		msg = appsecRuleName
	}

	r.WriteString(fmt.Sprintf(` "id:%d,phase:2,deny,log,msg:'%s',tag:'crowdsec-%s',tag:'cs-custom-rule'`, m.generateRuleID(rule, appsecRuleName, position), msg, appsecRuleName))

	if severity != "" && isRoot {
		r.WriteString(fmt.Sprintf(`,severity:'%s'`, severity))
	}

	for _, transform := range rule.Transform {
		if transform == "" || (hasCount && transform == "count") {
			continue
		}

		r.WriteByte(',')

		mappedTransform, ok := transformMap[transform]
		if !ok {
			return "", fmt.Errorf("unknown transform '%s'", transform)
		}

		r.WriteString(mappedTransform)
	}

	if rule.BodyType != "" {
		mappedBodyType, ok := bodyTypeMatch[rule.BodyType]
		if !ok {
			return "", fmt.Errorf("unknown body type '%s'", rule.BodyType)
		}

		r.WriteString(fmt.Sprintf(",ctl:requestBodyProcessor=%s", mappedBodyType))
	}

	if chain {
		r.WriteString(",chain")
	}

	if skip > 0 {
		r.WriteString(fmt.Sprintf(",skip:%d", skip))
	}

	r.WriteByte('"')

	return r.String(), nil
}
