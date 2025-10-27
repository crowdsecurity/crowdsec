package leakybucket

import (
	"github.com/expr-lang/expr/vm"
)

type ScopeType struct {
	Scope         string `yaml:"type"`
	Filter        string `yaml:"expression"`
	RunTimeFilter *vm.Program
}
