package appsec_rule

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

	cztypes "github.com/corazawaf/coraza/v3/types"
)

type ModsecurityRule struct {
	ids []uint32
}

// Zone represents a modsecurity zone with its properties
type Zone struct {
	ModsecName   string // The actual modsecurity variable name
	MinimumPhase int    // Minimum phase required for this zone
}

// String returns the modsecurity variable name
func (z Zone) String() string {
	return z.ModsecName
}

// RequiresPhase2 returns true if this zone requires phase 2
func (z Zone) RequiresPhase2() bool {
	return z.MinimumPhase >= 2
}

// GetZone safely retrieves a zone by name
func GetZone(name string) (Zone, bool) {
	zone, exists := zones[name]
	return zone, exists
}

// zones defines all available zones with their properties
var zones = map[string]Zone{
	"ARGS":             {ModsecName: "ARGS_GET", MinimumPhase: 1},
	"ARGS_NAMES":       {ModsecName: "ARGS_GET_NAMES", MinimumPhase: 1},
	"BODY_ARGS":        {ModsecName: "ARGS_POST", MinimumPhase: 2},
	"BODY_ARGS_NAMES":  {ModsecName: "ARGS_POST_NAMES", MinimumPhase: 2},
	"COOKIES":          {ModsecName: "REQUEST_COOKIES", MinimumPhase: 1},
	"COOKIES_NAMES":    {ModsecName: "REQUEST_COOKIES_NAMES", MinimumPhase: 1},
	"FILES":            {ModsecName: "FILES", MinimumPhase: 2},
	"FILES_NAMES":      {ModsecName: "FILES_NAMES", MinimumPhase: 2},
	"FILES_TOTAL_SIZE": {ModsecName: "FILES_COMBINED_SIZE", MinimumPhase: 2},
	"HEADERS_NAMES":    {ModsecName: "REQUEST_HEADERS_NAMES", MinimumPhase: 1},
	"HEADERS":          {ModsecName: "REQUEST_HEADERS", MinimumPhase: 1},
	"METHOD":           {ModsecName: "REQUEST_METHOD", MinimumPhase: 1},
	"PROTOCOL":         {ModsecName: "REQUEST_PROTOCOL", MinimumPhase: 1},
	"URI":              {ModsecName: "REQUEST_FILENAME", MinimumPhase: 1},
	"URI_FULL":         {ModsecName: "REQUEST_URI", MinimumPhase: 1},
	"RAW_BODY":         {ModsecName: "RAW_REQUEST_BODY", MinimumPhase: 2},
	"FILENAMES":        {ModsecName: "FILES", MinimumPhase: 2},
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

func (m *ModsecurityRule) Build(rule *CustomRule, appsecRuleName string, appsecRuleDescription string) (string, []uint32, error) {
	//Validate severity
	if rule.Severity == "" {
		rule.Severity = cztypes.RuleSeverityEmergency.String()
	}
	_, err := cztypes.ParseRuleSeverity(rule.Severity)
	if err != nil {
		return "", nil, err
	}

	rules, err := m.buildRules(rule, appsecRuleName, appsecRuleDescription, false, 0, 0, true)
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

func (m *ModsecurityRule) buildRules(rule *CustomRule, appsecRuleName string, appsecRuleDescription string, and bool, toSkip int, depth int, isRoot bool) ([]string, error) {
	return m.buildRulesWithPhase(rule, appsecRuleName, appsecRuleDescription, and, toSkip, depth, isRoot, 0)
}

func (m *ModsecurityRule) buildRulesWithPhase(rule *CustomRule, appsecRuleName string, appsecRuleDescription string, and bool, toSkip int, depth int, isRoot bool, forcedPhase int) ([]string, error) {
	ret := make([]string, 0)

	if len(rule.And) != 0 && len(rule.Or) != 0 {
		return nil, errors.New("cannot have both 'and' and 'or' in the same rule")
	}

	if rule.And != nil {
		// For chained rules (AND), all must be in the same phase
		// Find the highest required phase for all rules in the chain
		// Also respect forcedPhase from parent (e.g., if inside an OR that requires phase 2)
		chainPhase := max(forcedPhase, m.determineChainPhase(rule))
		for c, andRule := range rule.And {
			depth++
			andRule.Severity = rule.Severity
			lastRule := c == len(rule.And)-1 // || len(rule.Or) == 0
			root := c == 0
			rules, err := m.buildRulesWithPhase(&andRule, appsecRuleName, appsecRuleDescription, !lastRule, 0, depth, root, chainPhase)
			if err != nil {
				return nil, err
			}
			ret = append(ret, rules...)
		}
	}

	if rule.Or != nil {
		// For OR rules using skip, all must be in the same phase
		// Determine the max phase needed across all OR rules
		// Also respect forcedPhase from parent (e.g., if inside an AND chain that requires phase 2)
		orPhase := max(forcedPhase, m.determineOrPhase(rule))
		for c, orRule := range rule.Or {
			depth++
			orRule.Severity = rule.Severity
			skip := len(rule.Or) - c - 1
			root := c == 0
			rules, err := m.buildRulesWithPhase(&orRule, appsecRuleName, appsecRuleDescription, false, skip, depth, root, orPhase)
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
		zoneInfo, ok := GetZone(zone)
		if !ok {
			return nil, fmt.Errorf("unknown zone '%s'", zone)
		}
		if len(rule.Variables) == 0 {
			r.WriteString(zoneInfo.ModsecName)
		} else {
			for j, variable := range rule.Variables {
				if j > 0 {
					r.WriteByte('|')
				}
				r.WriteString(fmt.Sprintf("%s%s:%s%s", zone_prefix, zoneInfo.ModsecName, variable_prefix, variable))
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

	var msg string
	if appsecRuleDescription != "" {
		msg = appsecRuleDescription
	} else {
		msg = appsecRuleName
	}

	// Determine optimal phase for this rule
	phase := m.determineOptimalPhase(rule, forcedPhase)
	r.WriteString(fmt.Sprintf(` "id:%d,phase:%d,deny,log,msg:'%s',tag:'crowdsec-%s',tag:'cs-custom-rule'`, m.generateRuleID(rule, appsecRuleName, depth), phase, msg, appsecRuleName))

	if rule.Severity != "" && isRoot { // Only put severity on the root rule
		r.WriteString(fmt.Sprintf(`,severity:'%s'`, rule.Severity))
	}

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

// determineOptimalPhase determines the optimal phase for a rule based on its zones
func (*ModsecurityRule) determineOptimalPhase(rule *CustomRule, forcedPhase int) int {
	minPhase := 1

	// If rule has body type specified, it requires phase 2
	if rule.BodyType != "" {
		minPhase = 2
	}

	// Check all zones used by this rule
	for _, zoneName := range rule.Zones {
		zoneInfo, ok := GetZone(zoneName)
		if !ok {
			// Unknown zone, default to phase 2 for safety
			minPhase = 2
			break
		}

		// If any zone requires phase 2, the whole rule must be phase 2
		if zoneInfo.RequiresPhase2() {
			minPhase = 2
			break
		}
	}

	// Return the higher of forcedPhase and the rule's minimum required phase
	return max(forcedPhase, minPhase)
}

// determineChainPhase determines the required phase for a chain of AND rules
func (m *ModsecurityRule) determineChainPhase(rule *CustomRule) int {
	// Check the current rule
	maxPhase := m.determineOptimalPhase(rule, 0)

	// Check all AND rules in the chain
	for _, andRule := range rule.And {
		maxPhase = max(maxPhase, m.determineOptimalPhase(&andRule, 0))

		// Recursively check nested AND chains
		if len(andRule.And) > 0 {
			maxPhase = max(maxPhase, m.determineChainPhase(&andRule))
		}

		// Also check nested OR rules within AND children
		if len(andRule.Or) > 0 {
			maxPhase = max(maxPhase, m.determineOrPhase(&andRule))
		}
	}

	return max(maxPhase, 1)
}

// determineOrPhase determines the required phase for OR rules (using skip)
// All OR rules must be in the same phase for skip to work correctly
func (m *ModsecurityRule) determineOrPhase(rule *CustomRule) int {
	maxPhase := m.determineOptimalPhase(rule, 0)

	// Check all OR rules
	for _, orRule := range rule.Or {
		maxPhase = max(maxPhase, m.determineOptimalPhase(&orRule, 0))

		// Recursively check nested OR rules
		if len(orRule.Or) > 0 {
			maxPhase = max(maxPhase, m.determineOrPhase(&orRule))
		}

		// Also check nested AND rules within OR branches
		if len(orRule.And) > 0 {
			maxPhase = max(maxPhase, m.determineChainPhase(&orRule))
		}
	}

	return max(maxPhase, 1)
}
