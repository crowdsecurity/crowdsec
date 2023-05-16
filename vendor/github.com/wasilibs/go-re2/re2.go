package re2

import (
	"regexp"

	"github.com/wasilibs/go-re2/internal"
)

type Regexp = internal.Regexp

// MatchString reports whether the string s
// contains any match of the regular expression pattern.
// More complicated queries need to use Compile and the full Regexp interface.
func MatchString(pattern string, s string) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	defer internal.Release(re)
	return re.MatchString(s), nil
}

// Match reports whether the byte slice b
// contains any match of the regular expression pattern.
// More complicated queries need to use Compile and the full Regexp interface.
func Match(pattern string, b []byte) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	defer internal.Release(re)
	return re.Match(b), nil
}

// Compile parses a regular expression and returns, if successful,
// a Regexp object that can be used to match against text.
//
// When matching against text, the regexp returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses the one that a backtracking search would have found first.
// This so-called leftmost-first matching is the same semantics
// that Perl, Python, and other implementations use, although this
// package implements it without the expense of backtracking.
// For POSIX leftmost-longest matching, see CompilePOSIX.
func Compile(expr string) (*Regexp, error) {
	return internal.Compile(expr, internal.CompileOptions{})
}

// CompilePOSIX is like Compile but restricts the regular expression
// to POSIX ERE (egrep) syntax and changes the match semantics to
// leftmost-longest.
//
// That is, when matching against text, the regexp returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses a match that is as long as possible.
// This so-called leftmost-longest matching is the same semantics
// that early regular expression implementations used and that POSIX
// specifies.
//
// However, there can be multiple leftmost-longest matches, with different
// submatch choices, and here this package diverges from POSIX.
// Among the possible leftmost-longest matches, this package chooses
// the one that a backtracking search would have found first, while POSIX
// specifies that the match be chosen to maximize the length of the first
// subexpression, then the second, and so on from left to right.
// The POSIX rule is computationally prohibitive and not even well-defined.
// See https://swtch.com/~rsc/regexp/regexp2.html#posix for details.
func CompilePOSIX(expr string) (*Regexp, error) {
	return internal.Compile(expr, internal.CompileOptions{Longest: true, Posix: true})
}

// MustCompile is like Compile but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables holding compiled regular
// expressions.
func MustCompile(str string) *Regexp {
	re, err := Compile(str)
	if err != nil {
		panic(`regexp: Compile(` + internal.QuoteForError(str) + `): ` + err.Error())
	}
	return re
}

// MustCompilePOSIX is like CompilePOSIX but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables holding compiled regular
// expressions.
func MustCompilePOSIX(str string) *Regexp {
	regexp, err := CompilePOSIX(str)
	if err != nil {
		panic(`regexp: CompilePOSIX(` + internal.QuoteForError(str) + `): ` + err.Error())
	}
	return regexp
}

// QuoteMeta returns a string that escapes all regular expression metacharacters
// inside the argument text; the returned string is a regular expression matching
// the literal text.
func QuoteMeta(s string) string {
	return regexp.QuoteMeta(s)
}
