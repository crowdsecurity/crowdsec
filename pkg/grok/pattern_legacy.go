package grok

import "regexp"

// Pattern is a pattern.
// Feel free to use the Pattern as regexp.Regexp.
type PatternLegacy struct {
	*regexp.Regexp
	s map[string]int
	// literals every matching input must contain, checked before the engine runs
	requiredLiterals []string
}

// ParseInto writes the captures into dest and reports whether anything was written.
func (p *PatternLegacy) ParseInto(input string, dest map[string]string) bool {
	// without semantics there is nothing to write, and callers read "no captures" as a failure
	if len(p.s) == 0 {
		return false
	}
	if !canMatch(p.requiredLiterals, input) {
		return false
	}
	ss := p.FindStringSubmatch(input)
	if len(ss) <= 1 {
		return false
	}
	for sem, order := range p.s {
		dest[sem] = ss[order]
	}
	return true
}

// Names returns all names that this pattern has
func (p *PatternLegacy) Names() (ss []string) {
	ss = make([]string, 0, len(p.s))
	for k := range p.s {
		ss = append(ss, k)
	}
	return ss
}
