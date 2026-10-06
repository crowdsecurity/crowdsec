package exprhelpers

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/builtin"
	"github.com/expr-lang/expr/parser"
	"gopkg.in/yaml.v3"
)

var macroNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// macros maps a macro name to its expression. It is replaced as a whole by
// LoadMacros, never mutated, so patchers can hold on to the map they got.
var macros map[string]string

// macroExpander replaces each zero-argument call to a macro with the macro's
// expression. Working on the AST rather than the source text keeps
// precedence intact: !IsFoo() negates the whole macro.
type macroExpander struct {
	macros map[string]string
}

func (m macroExpander) Visit(node *ast.Node) { //nolint:gocritic // signature imposed by ast.Visitor
	name, ok := macroCall(*node)
	if !ok {
		return
	}

	body, ok := m.macros[name]
	if !ok {
		return
	}

	// Parse a fresh tree on every expansion: the checker annotates nodes in place,
	// so a tree can't be shared between compilations. Bodies were validated by LoadMacros.
	tree, err := parser.Parse(body)
	if err != nil {
		return
	}

	// Walk is post-order and won't visit the subtree we're about to splice in,
	// so expand nested macros here. LoadMacros rejects cycles.
	ast.Walk(&tree.Node, m)
	ast.Patch(node, tree.Node)
}

// macroCall returns the callee name if node is a call without arguments to a plain identifier.
func macroCall(node ast.Node) (string, bool) {
	call, ok := node.(*ast.CallNode)
	if !ok || len(call.Arguments) > 0 {
		return "", false
	}

	ident, ok := call.Callee.(*ast.IdentifierNode)
	if !ok {
		return "", false
	}

	return ident.Value, true
}

func macroOption() (expr.Option, bool) {
	if len(macros) == 0 {
		return nil, false
	}

	return expr.Patch(macroExpander{macros: macros}), true
}

// LoadMacros reads every .yaml/.yml file in dir and returns how many macros were loaded.
// Each file is a mapping of macro name to expression. A missing directory means no macros.
func LoadMacros(dir string) (int, error) {
	loaded, err := readMacroDir(dir)
	if err != nil {
		return 0, err
	}

	if err := validateMacros(loaded); err != nil {
		return 0, err
	}

	macros = loaded

	return len(loaded), nil
}

func readMacroDir(dir string) (map[string]string, error) {
	loaded := map[string]string{}

	if dir == "" {
		return loaded, nil
	}

	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return loaded, nil
	}

	if err != nil {
		return nil, fmt.Errorf("reading macro directory: %w", err)
	}

	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if entry.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		fileMacros := map[string]string{}
		if err := yaml.Unmarshal(content, &fileMacros); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}

		for name, body := range fileMacros {
			if _, dup := loaded[name]; dup {
				return nil, fmt.Errorf("%s: macro %q is already defined", path, name)
			}

			loaded[name] = body
		}
	}

	return loaded, nil
}

func validateMacros(m map[string]string) error {
	deps := make(map[string][]string, len(m))

	for name, body := range m {
		if !macroNamePattern.MatchString(name) {
			return fmt.Errorf("macro %q: invalid name", name)
		}

		if _, ok := builtin.Index[name]; ok {
			return fmt.Errorf("macro %q: conflicts with a builtin function", name)
		}

		if slices.ContainsFunc(exprFuncs, func(f exprCustomFunc) bool { return f.name == name }) {
			return fmt.Errorf("macro %q: conflicts with a crowdsec function", name)
		}

		if strings.TrimSpace(body) == "" {
			return fmt.Errorf("macro %q: empty expression", name)
		}

		tree, err := parser.Parse(body)
		if err != nil {
			return fmt.Errorf("macro %q: %w", name, err)
		}

		deps[name] = macroRefs(tree.Node, m)
	}

	return checkMacroCycles(deps)
}

// macroRefs lists the macros called (without arguments) by node.
func macroRefs(node ast.Node, m map[string]string) []string {
	var refs []string

	ast.Find(node, func(n ast.Node) bool {
		if name, ok := macroCall(n); ok {
			if _, isMacro := m[name]; isMacro {
				refs = append(refs, name)
			}
		}

		return false
	})

	return refs
}

func checkMacroCycles(deps map[string][]string) error {
	const (
		visiting = 1
		done     = 2
	)

	state := make(map[string]int, len(deps))

	var visit func(name string, path []string) error

	visit = func(name string, path []string) error {
		switch state[name] {
		case done:
			return nil
		case visiting:
			return fmt.Errorf("macro %q: recursive definition (%s)", name, strings.Join(append(path, name), " -> "))
		}

		state[name] = visiting

		for _, dep := range deps[name] {
			if err := visit(dep, append(path, name)); err != nil {
				return err
			}
		}

		state[name] = done

		return nil
	}

	names := make([]string, 0, len(deps))
	for name := range deps {
		names = append(names, name)
	}

	slices.Sort(names)

	for _, name := range names {
		if err := visit(name, nil); err != nil {
			return err
		}
	}

	return nil
}
