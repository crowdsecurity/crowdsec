package exprhelpers

import (
	"reflect"
	"testing"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

type ExprDbgTest struct {
	Name                  string
	Expr                  string
	ExpectedOutputs       []OpOutput
	ExpectedFailedCompile bool
	ExpectedFailRuntime   bool
	Env                   map[string]interface{}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestBaseDbg(t *testing.T) {
	defaultEnv := map[string]interface{}{
		"queue":        &types.Queue{},
		"evt":          &types.Event{},
		"sample_array": []string{"a", "b", "c"},
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
	tests := []ExprDbgTest{
		{
			Name: "base string cmp",
			Expr: "base_string == 'hello world'",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{
					Comparison:         true,
					Left:               "hello world",
					Right:              "hello world",
					StrConditionResult: "true",
					ConditionResult:    boolPtr(true),
				},
			},
		},
		{
			Name: "base function call",
			Expr: "Upper(sample_array[1]) == 'B'",
			Env:  defaultEnv,
			ExpectedOutputs: []OpOutput{
				{
					Func:        true,
					FuncName:    "Upper",
					Args:        []string{"b"},
					FuncResults: []string{"B"},
				},
			},
		},
	}

	logger := log.WithField("test", "exprhelpers")
	for _, test := range tests {
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
		outdbg, _, err := RunWithDebug(prog, test.Env, logger)
		if test.ExpectedFailRuntime {
			if err == nil {
				t.Fatalf("test %s : expected runtime error", test.Name)
			}
		} else {
			if err != nil {
				t.Fatalf("test %s : unexpected runtime error : %s", test.Name, err)
			}
		}
		if len(outdbg) != len(test.ExpectedOutputs) {
			t.Fatalf("test %s : expected %d outputs, got %d", test.Name, len(test.ExpectedOutputs), len(outdbg))
		}
		for i, out := range outdbg {
			if !reflect.DeepEqual(out, test.ExpectedOutputs[i]) {
				t.Fatalf("test %s : expected output %d : %+v, got %+v", test.Name, i, test.ExpectedOutputs[i], out)
			}
		}
	}
}
