package exprhelpers

import (
	"reflect"
	"testing"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

type ExprDbgTest struct {
	Name                  string
	Expr                  string
	ExpectedOutputs       []OpOutput
	ExpectedFailedCompile bool
	ExpectedFailRuntime   bool
	Env                   map[string]interface{}
	LogLevel              log.Level
}

func boolPtr(b bool) *bool {
	return &b
}

func TestBaseDbg(t *testing.T) {
	defaultEnv := map[string]interface{}{
		"queue":        &types.Queue{},
		"evt":          &types.Event{},
		"sample_array": []string{"a", "b", "c", "ZZ"},
		"base_string":  "hello world",
		"base_int":     42,
		"base_float":   42.42,
		"base_struct": struct {
			Foo   string
			Bar   int
			Myarr []string
		}{
			Foo:   "bar",
			Bar:   42,
			Myarr: []string{"a", "b", "c"},
		},
	}
	// tips for the tests:
	// use '%#v' to dump in golang syntax
	// use regexp to clear empty/default fields:
	// [a-z]+: (false|\[\]string\(nil\)|""),

	//Missing multi parametes function
	//MultiLine
	tests := []ExprDbgTest{
		{
			Name: "loop with func call",
			Expr: "count(base_struct.Myarr, {Upper(#) == 'C'}) == 1",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "count(base_struct.Myarr, {Upper(", CodeDepth: 4, BlockStart: true, Finalized: false},
				{Code: "Upper(#) == ", CodeDepth: 4, Func: true, FuncName: "Upper", Args: []string{"a"}, FuncResults: []string{"A"}, Finalized: true},
				{Code: "== 'C'}) == ", CodeDepth: 4, Comparison: true, Left: "A", Right: "C", StrConditionResult: "[false]", ConditionResult: boolPtr(false), Finalized: true},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 4, JumpIf: true, IfFalse: true, StrConditionResult: "false", ConditionResult: boolPtr(false), Finalized: false},
				{Code: "Upper(#) == ", CodeDepth: 4, Func: true, FuncName: "Upper", Args: []string{"b"}, FuncResults: []string{"B"}, Finalized: true},
				{Code: "== 'C'}) == ", CodeDepth: 4, Comparison: true, Left: "B", Right: "C", StrConditionResult: "[false]", ConditionResult: boolPtr(false), Finalized: true},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 4, JumpIf: true, IfFalse: true, StrConditionResult: "false", ConditionResult: boolPtr(false), Finalized: false},
				{Code: "Upper(#) == ", CodeDepth: 4, Func: true, FuncName: "Upper", Args: []string{"c"}, FuncResults: []string{"C"}, Finalized: true},
				{Code: "== 'C'}) == ", CodeDepth: 4, Comparison: true, Left: "C", Right: "C", StrConditionResult: "[true]", ConditionResult: boolPtr(true), Finalized: true},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 4, JumpIf: true, IfFalse: true, StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: false},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 0, BlockEnd: true, StrConditionResult: "[1]", Finalized: false},
				{Code: "== 1", CodeDepth: 0, Comparison: true, Left: "1", Right: "1", StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "loop with func call and extra check",
			Expr: "count(base_struct.Myarr, {Upper(#) == 'C'}) == 1 && Upper(base_struct.Foo) == 'BAR'",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "count(base_struct.Myarr, {Upper(", CodeDepth: 4, BlockStart: true, ConditionResult: (*bool)(nil), Finalized: false},
				{Code: "Upper(#) == ", CodeDepth: 4, Func: true, FuncName: "Upper", Args: []string{"a"}, FuncResults: []string{"A"}, ConditionResult: (*bool)(nil), Finalized: true},
				{Code: "== 'C'}) == ", CodeDepth: 4, Comparison: true, Left: "A", Right: "C", StrConditionResult: "[false]", ConditionResult: boolPtr(false), Finalized: true},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 4, JumpIf: true, IfFalse: true, StrConditionResult: "false", ConditionResult: boolPtr(false), Finalized: false},
				{Code: "Upper(#) == ", CodeDepth: 4, Func: true, FuncName: "Upper", Args: []string{"b"}, FuncResults: []string{"B"}, ConditionResult: (*bool)(nil), Finalized: true},
				{Code: "== 'C'}) == ", CodeDepth: 4, Comparison: true, Left: "B", Right: "C", StrConditionResult: "[false]", ConditionResult: boolPtr(false), Finalized: true},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 4, JumpIf: true, IfFalse: true, StrConditionResult: "false", ConditionResult: boolPtr(false), Finalized: false},
				{Code: "Upper(#) == ", CodeDepth: 4, Func: true, FuncName: "Upper", Args: []string{"c"}, FuncResults: []string{"C"}, ConditionResult: (*bool)(nil), Finalized: true},
				{Code: "== 'C'}) == ", CodeDepth: 4, Comparison: true, Left: "C", Right: "C", StrConditionResult: "[true]", ConditionResult: boolPtr(true), Finalized: true},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 4, JumpIf: true, IfFalse: true, StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: false},
				{Code: "count(base_struct.Myarr, {Upper(#) == 'C'}) == ", CodeDepth: 0, BlockEnd: true, StrConditionResult: "[1]", ConditionResult: (*bool)(nil), Finalized: false},
				{Code: "== 1 ", CodeDepth: 0, Comparison: true, Left: "1", Right: "1", StrConditionResult: "[true]", ConditionResult: boolPtr(true), Finalized: true},
				{Code: "&& Upper(", CodeDepth: 0, JumpIf: true, IfFalse: true, StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: false},
				{Code: "Upper(base_struct.Foo) == ", CodeDepth: 0, Func: true, FuncName: "Upper", Args: []string{"bar"}, FuncResults: []string{"BAR"}, ConditionResult: (*bool)(nil), Finalized: true},
				{Code: "== 'BAR'", CodeDepth: 0, Comparison: true, Left: "BAR", Right: "BAR", StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "base 'in' test",
			Expr: "base_int in [1,2,3,4,42]",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "in [1,2,3,4,42]", CodeDepth: 0, Args: []string{"42", "map[1:{} 2:{} 3:{} 4:{} 42:{}]"}, Condition: true, ConditionIn: true, StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "base string cmp",
			Expr: "base_string == 'hello world'",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "== 'hello world'", CodeDepth: 0, Comparison: true, Left: "hello world", Right: "hello world", StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "base int cmp",
			Expr: "base_int == 42",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "== 42", CodeDepth: 0, Comparison: true, Left: "42", Right: "42", StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "negative check",
			Expr: "base_int != 43",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "!= 43", CodeDepth: 0, Negated: true, Comparison: true, Left: "42", Right: "43", StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "testing ORs",
			Expr: "base_int == 43 || base_int == 42",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "== 43 ", CodeDepth: 0, Comparison: true, Left: "42", Right: "43", StrConditionResult: "[false]", ConditionResult: boolPtr(false), Finalized: true},
				{Code: "|| ", CodeDepth: 0, JumpIf: true, IfTrue: true, StrConditionResult: "false", ConditionResult: boolPtr(false), Finalized: false},
				{Code: "== 42", CodeDepth: 0, Comparison: true, Left: "42", Right: "42", StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "testing basic true",
			Expr: "true",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "true", CodeDepth: 0, Condition: true, StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
		{
			Name: "testing basic false",
			Expr: "false",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{Code: "false", CodeDepth: 0, Condition: true, StrConditionResult: "false", ConditionResult: boolPtr(false), Finalized: true},
			},
		},
		{
			Name: "testing multi lines",
			Expr: `base_int == 42 &&
			base_string == 'hello world' &&
			(base_struct.Bar == 41 || base_struct.Bar == 42)`,
			Env:      defaultEnv,
			LogLevel: log.TraceLevel,
			ExpectedOutputs: []OpOutput{
				{Code: "== 42 ", CodeDepth: 0, Comparison: true, Left: "42", Right: "42", StrConditionResult: "[true]", ConditionResult: boolPtr(true), Finalized: true},
				{Code: "&&\t\t\t", CodeDepth: 0, JumpIf: true, IfFalse: true, StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: false},
				{Code: "== 'hello world' ", CodeDepth: 0, Comparison: true, Left: "hello world", Right: "hello world", StrConditionResult: "[true]", ConditionResult: boolPtr(true), Finalized: true},
				{Code: "&&\t\t\t(", CodeDepth: 0, JumpIf: true, IfFalse: true, StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: false},
				{Code: "== 41 ", CodeDepth: 0, Comparison: true, Left: "42", Right: "41", StrConditionResult: "[false]", ConditionResult: boolPtr(false), Finalized: true},
				{Code: "|| ", CodeDepth: 0, JumpIf: true, IfTrue: true, StrConditionResult: "false", ConditionResult: boolPtr(false), Finalized: false},
				{Code: "== 42)", CodeDepth: 0, Comparison: true, Left: "42", Right: "42", StrConditionResult: "true", ConditionResult: boolPtr(true), Finalized: true},
			},
		},
	}

	logger := log.WithField("test", "exprhelpers")
	for _, test := range tests {
		if test.LogLevel != 0 {
			log.SetLevel(test.LogLevel)
		} else {
			log.SetLevel(log.DebugLevel)
		}
		prog, err := expr.Compile(test.Expr, GetExprOptions(test.Env)...)
		if test.ExpectedFailRuntime {
			if err == nil {
				t.Fatalf("test %s : expected compile error", test.Name)
			}
		} else {
			if err != nil {
				t.Fatalf("test %s : unexpected compile error : %s", test.Name, err)
			}
		}
		outdbg, ret, err := RunWithDebug(prog, test.Env, logger)
		if test.ExpectedFailRuntime {
			if err == nil {
				t.Fatalf("test %s : expected runtime error", test.Name)
			}
		} else {
			if err != nil {
				t.Fatalf("test %s : unexpected runtime error : %s", test.Name, err)
			}
		}
		log.SetLevel(log.DebugLevel)
		DisplayExprDebug(prog, outdbg, logger, ret)
		if len(outdbg) != len(test.ExpectedOutputs) {
			t.Errorf("failed test %s", test.Name)
			t.Errorf("%#v", outdbg)
			//out, _ := yaml.Marshal(outdbg)
			//fmt.Printf("%s", string(out))
			t.Fatalf("test %s : expected %d outputs, got %d", test.Name, len(test.ExpectedOutputs), len(outdbg))

		}
		for i, out := range outdbg {
			if !reflect.DeepEqual(out, test.ExpectedOutputs[i]) {
				spew.Config.DisableMethods = true
				t.Errorf("failed test %s", test.Name)
				t.Errorf("expected : %#v", test.ExpectedOutputs[i])
				t.Errorf("got      : %#v", out)
				t.Fatalf("%d/%d    : mismatch", i, len(outdbg))
			}
			//DisplayExprDebug(prog, outdbg, logger, ret)
		}
	}
}
