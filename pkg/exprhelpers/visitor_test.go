package exprhelpers

import (
	"sort"
	"testing"

	"github.com/antonmedv/expr"
	log "github.com/sirupsen/logrus"
)

func TestVisitorBuild(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
		env  map[string]interface{}
	}{
		{
			name: "simple",
			expr: "evt.X",
			want: []string{"evt.X"},
			env: map[string]interface{}{
				"evt": map[string]interface{}{
					"X": 1,
				},
			},
		},
		{
			name: "two vars",
			expr: "evt.X && evt.Y",
			want: []string{"evt.X", "evt.Y"},
			env: map[string]interface{}{
				"evt": map[string]interface{}{
					"X": 1,
					"Y": 2,
				},
			},
		},
		{
			name: "in",
			expr: "evt.X in [1,2,3]",
			want: []string{"evt.X"},
			env: map[string]interface{}{
				"evt": map[string]interface{}{
					"X": 1,
				},
			},
		},
		{
			name: "in complex",
			expr: "evt.X in [1,2,3] && evt.Y in [1,2,3] || evt.Z in [1,2,3]",
			want: []string{"evt.X", "evt.Y", "evt.Z"},
			env: map[string]interface{}{
				"evt": map[string]interface{}{
					"X": 1,
					"Y": 2,
					"Z": 3,
				},
			},
		},
		{
			name: "function call",
			expr: "Foo(evt.X, 'ads')",
			want: []string{"evt.X"},
			env: map[string]interface{}{
				"evt": map[string]interface{}{
					"X": 1,
				},
				"Foo": func(x int, y string) int {
					return x
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &visitor{logger: log.NewEntry(log.New())}
			ret, err := v.Build(tt.expr, expr.Env(tt.env))
			if err != nil {
				t.Errorf("visitor.Build() error = %v", err)
				return
			}
			if len(ret.expression) != len(tt.want) {
				t.Errorf("visitor.Build() = %v, want %v", ret.expression, tt.want)
			}
			//Sort both slices as the order is not guaranteed ??
			sort.Slice(tt.want, func(i, j int) bool {
				return tt.want[i] < tt.want[j]
			})
			sort.Slice(ret.expression, func(i, j int) bool {
				return ret.expression[i].Str < ret.expression[j].Str
			})
			for idx, v := range ret.expression {
				if v.Str != tt.want[idx] {
					t.Errorf("visitor.Build() = %v, want %v", v.Str, tt.want[idx])
				}
			}
		})
	}
}
