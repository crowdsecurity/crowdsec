package appsec

import "github.com/expr-lang/expr/ast"

// This is not an actual patcher: we just walk the AST to check if we need to create a WASM VM for the challenge mode.
type appsecExprPatcher struct {
	NeedWASMVM bool
}

// challengeRuntimeCallees is the set of expr helper names whose presence in
// any compiled rule body implies that the challenge runtime (WASM VM,
// obfuscator, keyring) must be initialized.
var challengeRuntimeCallees = map[string]struct{}{
	"SendChallenge":        {},
	"GrantChallengeCookie": {},
	"RejectSubmission":     {},
	"LogAccepted":          {},
}

func (p *appsecExprPatcher) Visit(node *ast.Node) { //nolint:gocritic // signature fixed by expr-lang ast.Visitor interface
	if n, ok := (*node).(*ast.CallNode); ok {
		if _, needs := challengeRuntimeCallees[n.Callee.String()]; needs {
			p.NeedWASMVM = true
		}
	}
}
