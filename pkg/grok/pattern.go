package grok

type Pattern interface {
	FindStringSubmatch(s string) []string
	String() string
	Names() []string
	Parse(input string) map[string]string
	ParseInto(input string, dest map[string]string) bool
	NumSubexp() int
}
