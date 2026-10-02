package grok

import (
	"regexp/syntax"
	"slices"
	"strings"
)

const (
	// shorter literals appear in too many lines to be worth scanning for
	minLiteralLength = 3
	// a matching line is scanned once per literal, so bound what a match has to pay
	maxLiterals = 3
)

// extractRequiredLiterals returns substrings that every input matching pattern must contain,
// longest first.
func extractRequiredLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}

	// deliberately not Simplify()'d: unrolling bounded repeats only duplicates the single
	// characters around them, which the length filter drops anyway. Checked against every base
	// pattern — identical output, ~9k fewer allocations per pass over the pattern set.
	return filterLiterals(collectLiterals(re))
}

// filterLiterals drops what is not worth scanning for and keeps the most selective few.
func filterLiterals(literals []string) []string {
	seen := make(map[string]struct{})
	kept := make([]string, 0, maxLiterals)
	for _, lit := range literals {
		if len(lit) < minLiteralLength {
			continue
		}
		if _, ok := seen[lit]; ok {
			continue
		}
		seen[lit] = struct{}{}
		kept = append(kept, lit)
	}

	// longest first, so the most selective literal gets the chance to reject on its own
	slices.SortStableFunc(kept, func(a, b string) int { return len(b) - len(a) })

	out := make([]string, 0, maxLiterals)
	for _, lit := range kept {
		// a literal contained in one we already keep adds nothing: the longer one implies it
		if slices.ContainsFunc(out, func(k string) bool { return strings.Contains(k, lit) }) {
			continue
		}
		out = append(out, lit)
		if len(out) == maxLiterals {
			break
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// collectLiterals walks the syntax tree and returns the literals that every match contains.
func collectLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		// a case-insensitive literal cannot be looked for with strings.Contains
		if re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		return []string{string(re.Rune)}

	case syntax.OpConcat:
		// every child has to match, so every child's literals are required; adjacent ones are
		// glued together into longer, more selective strings
		var (
			out []string
			run strings.Builder
		)
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral && sub.Flags&syntax.FoldCase == 0 {
				run.WriteString(string(sub.Rune))
				continue
			}
			if run.Len() > 0 {
				out = append(out, run.String())
				run.Reset()
			}
			out = append(out, collectLiterals(sub)...)
		}
		if run.Len() > 0 {
			out = append(out, run.String())
		}
		return out

	case syntax.OpCapture, syntax.OpPlus:
		// a group is transparent, and x+ matches at least once
		return collectLiterals(re.Sub[0])

	case syntax.OpRepeat:
		if re.Min == 0 {
			return nil
		}
		return collectLiterals(re.Sub[0])

	default:
		// OpAlternate: only one branch has to match, so no branch is required.
		// OpStar, OpQuest: may match zero times.
		// Char classes, anchors and the rest carry no literal.
		return nil
	}
}

// canMatch reports whether input could match. False means it definitely cannot.
func canMatch(literals []string, input string) bool {
	for _, lit := range literals {
		if !strings.Contains(input, lit) {
			return false
		}
	}
	return true
}
