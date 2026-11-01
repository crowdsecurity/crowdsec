package grok

import "regexp/syntax"

// compileFewerCaptures compiles expr with only the groups bound to a semantic left capturing,
// and returns s remapped accordingly. Every NFA thread carries a copy of all capture slots, so
// the unused groups (most of them: every %{SUB} is wrapped in one) make up most of the matching
// cost. expr is compiled as is when it can't be reduced.
func compileFewerCaptures[R compiledRegexp](expr string, s map[string]int, compile func(string) (R, error)) (R, map[string]int, error) {
	if reduced, rs, groups, ok := reduceCaptures(expr, s); ok {
		// the reduced expression comes from printing an edited tree: a group count that
		// doesn't add up means the printer didn't round-trip it, and rs can't be trusted
		if r, err := compile(reduced); err == nil && r.NumSubexp() == groups {
			return r, rs, nil
		}
	}
	r, err := compile(expr)
	return r, s, err
}

// reduceCaptures returns expr where every capturing group not referenced by s is turned
// into a non-capturing group, s remapped to the new group indexes, and how many groups are
// left. ok is false if expr can't be reduced or if there is nothing to gain.
func reduceCaptures(expr string, s map[string]int) (reduced string, rs map[string]int, groups int, ok bool) {
	if len(s) == 0 {
		return "", nil, 0, false
	}
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", nil, 0, false
	}
	n := re.MaxCap()
	keep := make(map[int]bool, len(s))
	for _, v := range s {
		if v < 1 || v > n {
			return "", nil, 0, false
		}
		keep[v] = true
	}
	if len(keep) == n {
		return "", nil, 0, false
	}
	remap := make(map[int]int, len(keep))
	re = stripCaptures(re, keep, remap)
	rs = make(map[string]int, len(s))
	for k, v := range s {
		rs[k] = remap[v]
	}
	return re.String(), rs, len(remap), true
}

// stripCaptures replaces the capturing groups not in keep with their content, and fills
// remap with the new indexes of kept groups, in order of their left parenthesis.
func stripCaptures(re *syntax.Regexp, keep map[int]bool, remap map[int]int) *syntax.Regexp {
	if re.Op == syntax.OpCapture {
		if !keep[re.Cap] {
			return stripCaptures(re.Sub[0], keep, remap)
		}
		remap[re.Cap] = len(remap) + 1
	}
	for i, sub := range re.Sub {
		re.Sub[i] = stripCaptures(sub, keep, remap)
	}
	return re
}
