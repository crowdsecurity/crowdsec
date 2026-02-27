package appsec

import "github.com/expr-lang/expr/ast"

// This is not an actual patcher: we just walk the AST to check if we need to create a WASM VM for the challenge mode.
type appsecExprPatcher struct {
	NeedWASMVM bool
}

func (p *appsecExprPatcher) Visit(node *ast.Node) {
	if n, ok := (*node).(*ast.CallNode); ok && n.Callee.String() == "RequireValidChallenge" {
		p.NeedWASMVM = true
	}
}
