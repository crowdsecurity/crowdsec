package grok

import (
	"github.com/wasilibs/go-re2"
)

// Pattern is a pattern.
// Feel free to use the Pattern as regexp.Regexp.
type PatternRe2 struct {
	*re2.Regexp
	s map[string]int
}

// ParseInto writes the captures into dest and reports whether anything was written.
func (p *PatternRe2) ParseInto(input string, dest map[string]string) bool {
	// without semantics there is nothing to write, and callers read "no captures" as a failure
	if len(p.s) == 0 {
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
func (p *PatternRe2) Names() (ss []string) {
	ss = make([]string, 0, len(p.s))
	for k := range p.s {
		ss = append(ss, k)
	}
	return ss
}
