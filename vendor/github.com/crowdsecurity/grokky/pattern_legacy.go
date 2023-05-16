package grokky

import "regexp"

// Pattern is a pattern.
// Feel free to use the Pattern as regexp.Regexp.
type PatternLegacy struct {
	*regexp.Regexp
	s map[string]int
}

// Parse returns map (name->match) on input. The map can be empty.
func (p *PatternLegacy) Parse(input string) map[string]string {
	ss := p.FindStringSubmatch(input)
	r := make(map[string]string)
	if len(ss) <= 1 {
		return r
	}
	for sem, order := range p.s {
		r[sem] = ss[order]
	}
	return r
}

// Names returns all names that this pattern has
func (p *PatternLegacy) Names() (ss []string) {
	ss = make([]string, 0, len(p.s))
	for k := range p.s {
		ss = append(ss, k)
	}
	return
}
