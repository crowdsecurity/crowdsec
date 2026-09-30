package appsec

import (
	"fmt"

	"github.com/expr-lang/expr/ast"
)

// This is not an actual patcher: we just walk the AST to check if we need to create a WASM VM for the challenge mode,
// and to collect the RateLimit() calls.
type appsecExprPatcher struct {
	NeedWASMVM bool

	// Every RateLimit() call site, by key. The limit is read here rather than
	// at request time so a bad one fails the config load.
	RateLimits map[string]rateLimitSpec
	// Visit can't return an error; the first one is kept for Hook.Build.
	err error
}

// challengeRuntimeCallees is the set of expr helper names whose presence in
// any compiled rule body implies that the challenge runtime (WASM VM,
// obfuscator, keyring) must be initialized.
var challengeRuntimeCallees = map[string]struct{}{
	"SendChallenge":        {},
	"GrantChallengeCookie": {},
	"RejectSubmission":     {},
	"LogAccepted":          {},
	// no runtime, no cookie validation: the helper would always return false
	"HasValidChallengeCookie": {},
}

func (p *appsecExprPatcher) Visit(node *ast.Node) { //nolint:gocritic // signature fixed by expr-lang ast.Visitor interface
	n, ok := (*node).(*ast.CallNode)
	if !ok {
		return
	}

	callee := n.Callee.String()

	if _, needs := challengeRuntimeCallees[callee]; needs {
		p.NeedWASMVM = true
	}

	if callee == rateLimitHelper && p.err == nil {
		p.err = p.collectRateLimit(n)
	}
}

func (p *appsecExprPatcher) collectRateLimit(n *ast.CallNode) error {
	args := n.Arguments
	// Present or not depending on whether expr.WithContext has run yet.
	if len(args) > 0 {
		if id, ok := args[0].(*ast.IdentifierNode); ok && id.Value == requestCtxVar {
			args = args[1:]
		}
	}

	// Arity is left to the type checker.
	if len(args) < 2 {
		return nil
	}

	key, ok := args[0].(*ast.StringNode)
	if !ok {
		return fmt.Errorf("%s: key must be a string literal", rateLimitHelper)
	}

	limit, ok := args[1].(*ast.StringNode)
	if !ok {
		return fmt.Errorf("%s(%q): limit must be a string literal", rateLimitHelper, key.Value)
	}

	spec, err := parseRateLimitSpec(key.Value, limit.Value)
	if err != nil {
		return err
	}

	if _, dup := p.RateLimits[spec.key]; dup {
		return fmt.Errorf("%s(%q): key is used by more than one call", rateLimitHelper, spec.key)
	}

	if p.RateLimits == nil {
		p.RateLimits = make(map[string]rateLimitSpec)
	}

	p.RateLimits[spec.key] = spec

	return nil
}
