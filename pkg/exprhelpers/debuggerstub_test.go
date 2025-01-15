//go:build !expr_debug
package exprhelpers

import (
	"testing"
)

func TestFailWithoutExprDebug(t *testing.T) {
	t.Fatal("To test pkg/exprhelpers, you need the expr_debug build tag")
}
