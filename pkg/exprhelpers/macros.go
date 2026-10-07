package exprhelpers

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/builtin"
	"github.com/expr-lang/expr/parser"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

var macroNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type macro struct {
	body string
	item string // name of the hub item defining the macro
}

// macros maps a macro name to its definition. It is replaced as a whole by
// LoadMacros, never mutated, so patchers can hold on to the map they got.
var macros map[string]macro

// macroExpander replaces each zero-argument call to a macro with the macro's
// expression. Working on the AST rather than the source text keeps
// precedence intact: !IsFoo() negates the whole macro.
type macroExpander struct {
	macros map[string]macro
}

func (m macroExpander) Visit(node *ast.Node) { //nolint:gocritic // signature imposed by ast.Visitor
	name, ok := macroCall(*node)
	if !ok {
		return
	}

	def, ok := m.macros[name]
	if !ok {
		return
	}

	// Parse a fresh tree on every expansion: the checker annotates nodes in place,
	// so a tree can't be shared between compilations. Bodies were validated by LoadMacros.
	tree, err := parser.Parse(def.body)
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

// LoadMacros replaces the current macros with those of the installed macro items,
// and returns how many were loaded. A nil hub means no macros.
func LoadMacros(hub *cwhub.Hub) (int, error) {
	var files []macroFile

	if hub != nil {
		for _, item := range hub.GetInstalledByType(cwhub.MACROS, true) {
			files = append(files, macroFile{item: item.Name, path: item.State.LocalPath})
		}
	}

	return loadMacroFiles(files)
}

type macroFile struct {
	item string
	path string
}

func loadMacroFiles(files []macroFile) (int, error) {
	loaded := map[string]macro{}

	for _, f := range files {
		content, err := os.ReadFile(f.path)
		if err != nil {
			return 0, err
		}

		// hub items carry metadata (name, description...) next to the macros
		var parsed struct {
			Macros map[string]string `yaml:"macros"`
		}

		if err := yaml.Unmarshal(content, &parsed); err != nil {
			return 0, fmt.Errorf("%s: %w", f.path, err)
		}

		if len(parsed.Macros) == 0 {
			return 0, fmt.Errorf("%s: no macros defined under the 'macros' key", f.path)
		}

		for name, body := range parsed.Macros {
			if prev, dup := loaded[name]; dup {
				return 0, fmt.Errorf("macro %q is defined by both %s and %s", name, prev.item, f.item)
			}

			loaded[name] = macro{body: body, item: f.item}
		}
	}

	if err := validateMacros(loaded); err != nil {
		return 0, err
	}

	macros = loaded

	return len(loaded), nil
}

func validateMacros(m map[string]macro) error {
	deps := make(map[string][]string, len(m))

	for name, def := range m {
		if !macroNamePattern.MatchString(name) {
			return fmt.Errorf("macro %q (%s): invalid name", name, def.item)
		}

		if _, ok := builtin.Index[name]; ok {
			return fmt.Errorf("macro %q (%s): conflicts with a builtin function", name, def.item)
		}

		if slices.ContainsFunc(exprFuncs, func(f exprCustomFunc) bool { return f.name == name }) {
			return fmt.Errorf("macro %q (%s): conflicts with a crowdsec function", name, def.item)
		}

		if strings.TrimSpace(def.body) == "" {
			return fmt.Errorf("macro %q (%s): empty expression", name, def.item)
		}

		tree, err := parser.Parse(def.body)
		if err != nil {
			return fmt.Errorf("macro %q (%s): %w", name, def.item, err)
		}

		deps[name] = macroRefs(tree.Node, m)
	}

	return checkMacroCycles(deps)
}

// MacroItems returns the sorted names of the hub items defining the macros
// that expression uses, directly or through other macros.
func MacroItems(expression string) ([]string, error) {
	tree, err := parser.Parse(expression)
	if err != nil {
		return nil, err
	}

	m := macros
	seen := map[string]bool{}
	items := []string{}

	var visit func(node ast.Node)

	visit = func(node ast.Node) {
		for _, name := range macroRefs(node, m) {
			if seen[name] {
				continue
			}

			seen[name] = true

			if !slices.Contains(items, m[name].item) {
				items = append(items, m[name].item)
			}

			// validated by LoadMacros
			sub, err := parser.Parse(m[name].body)
			if err != nil {
				continue
			}

			visit(sub.Node)
		}
	}

	visit(tree.Node)
	slices.Sort(items)

	return items, nil
}

// macroRefs lists the macros called (without arguments) by node.
func macroRefs(node ast.Node, m map[string]macro) []string {
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
