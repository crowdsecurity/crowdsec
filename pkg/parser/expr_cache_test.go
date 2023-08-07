package parser

import (
	"fmt"
	"testing"
)

func TestExprCache(t *testing.T) {
	tests := []struct {
		name                  string
		expressions           []string
		expected_unique_count int
	}{
		{
			name: "3 unique expressions",
			expressions: []string{
				"1==1",
				"1==2",
				"1==3",
			},
			expected_unique_count: 3,
		},
		{
			name: "2 unique expressions with 1 duplicate",
			expressions: []string{
				"1==1",
				"1==2",
				"1==1",
			},
			expected_unique_count: 2,
		},
		{
			name: "1 unique expression with 2 duplicates",
			expressions: []string{
				"1==1",
				"1==1",
				"1==1",
			},
			expected_unique_count: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_t *testing.T) {
			_u := make(map[string]bool, tt.expected_unique_count)
			cache := NewExprCache()
			for _, expr := range tt.expressions {
				program, err := cache.Get(expr, nil)
				if err != nil {
					t.Errorf("error while compiling expression: %s", err)
				}
				address := fmt.Sprintf("%p", program)
				if _, ok := _u[address]; !ok {
					_u[address] = true
				}
			}
			if len(_u) != tt.expected_unique_count {
				t.Errorf("expected %d unique expressions, got %d", tt.expected_unique_count, len(_u))
			}
		})
	}
}
