package grokky

type Pattern interface {
	FindStringSubmatch(s string) []string
	String() string
	Names() []string
	Parse(input string) map[string]string
	NumSubexp() int
}
