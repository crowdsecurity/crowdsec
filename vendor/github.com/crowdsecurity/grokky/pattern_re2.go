package grokky

import (
	"github.com/wasilibs/go-re2"
)

// Pattern is a pattern.
// Feel free to use the Pattern as regexp.Regexp.
type PatternRe2 struct {
	*re2.Regexp
	s map[string]int
}

// Parse returns map (name->match) on input. The map can be empty.
func (p *PatternRe2) Parse(input string) map[string]string {
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
func (p *PatternRe2) Names() (ss []string) {
	ss = make([]string, 0, len(p.s))
	for k := range p.s {
		ss = append(ss, k)
	}
	return
}
