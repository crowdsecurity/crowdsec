package grok

type Pattern interface {
	String() string
	Names() []string
	ParseInto(input string, dest map[string]string) bool
}
