package lexer

import (
	"fmt"

	"github.com/antonmedv/expr/file"
)

type Kind string

const (
	Identifier Kind = "Identifier"
	Number     Kind = "Number"
	String     Kind = "String"
	Operator   Kind = "Operator"
	Bracket    Kind = "Bracket"
	EOF        Kind = "EOF"
)

type Token struct {
	file.Location
	Kind  Kind
	Value string
}

func (t Token) String() string {
	if t.Value == "" {
		return string(t.Kind)
	}
	return fmt.Sprintf("%s(%#v)", t.Kind, t.Value)
}

func (t Token) Is(kind Kind, values ...string) bool {
	if len(values) == 0 {
		return kind == t.Kind
	}

	for _, v := range values {
		if v == t.Value {
			goto found
		}
	}
	return false

found:
	return kind == t.Kind
}
