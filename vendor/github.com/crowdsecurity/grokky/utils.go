package grokky

import (
	"regexp"
	"strings"
)

// helpers

func split(s string) (name, sem string) {
	ss := patternRegexp.FindStringSubmatch(s)
	if len(ss) >= 2 {
		name = ss[1]
	}
	if len(ss) >= 4 {
		sem = ss[3]
	}
	return
}

func wrap(s string) string { return "(" + s + ")" }

// http://play.golang.org/p/1rPuziYhRL

var (
	nonCapLeftRxp  = regexp.MustCompile(`\(\?[imsU\-]*\:`)
	nonCapFlagsRxp = regexp.MustCompile(`\(?[imsU\-]+\)`)
)

// cap count
func capCount(in string) int {
	leftParens := strings.Count(in, "(")
	nonCapLeft := len(nonCapLeftRxp.FindAllString(in, -1))
	nonCapBoth := len(nonCapFlagsRxp.FindAllString(in, -1))
	escapedLeftParens := strings.Count(in, `\(`)
	return leftParens - nonCapLeft - nonCapBoth - escapedLeftParens
}
