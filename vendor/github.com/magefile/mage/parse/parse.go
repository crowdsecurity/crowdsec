package parse

import (
	"errors"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/magefile/mage/internal"
)

const importTag = "mage:import"

var debug = log.New(ioutil.Discard, "DEBUG: ", log.Ltime|log.Lmicroseconds)

// EnableDebug turns on debug logging.
func EnableDebug() {
	debug.SetOutput(os.Stderr)
}

// PkgInfo contains inforamtion about a package of files according to mage's
// parsing rules.
type PkgInfo struct {
	AstPkg      *ast.Package
	DocPkg      *doc.Package
	Description string
	Funcs       Functions
	DefaultFunc *Function
	Aliases     map[string]*Function
	Imports     Imports
}

// Function represented a job function from a mage file
type Function struct {
	PkgAlias   string
	Package    string
	ImportPath string
	Name       string
	Receiver   string
	IsError    bool
	IsContext  bool
	Synopsis   string
	Comment    string
	Args       []Arg
}

var _ sort.Interface = (Functions)(nil)

// Functions implements sort interface to optimize compiled output with
// deterministic generated mainfile.
type Functions []*Function

func (s Functions) Len() int {
	return len(s)
}

func (s Functions) Less(i, j int) bool {
	return s[i].TargetName() < s[j].TargetName()
}

func (s Functions) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Arg is an argument to a Function.
type Arg struct {
	Name, Type string
}

// ID returns user-readable information about where this function is defined.
func (f Function) ID() string {
	path := "<current>"
	if f.ImportPath != "" {
		path = f.ImportPath
	}
	receiver := ""
	if f.Receiver != "" {
		receiver = f.Receiver + "."
	}
	return fmt.Sprintf("%s.%s%s", path, receiver, f.Name)
}

// TargetName returns the name of the target as it should appear when used from
// the mage cli.  It is always lowercase.
func (f Function) TargetName() string {
	var names []string

	for _, s := range []string{f.PkgAlias, f.Receiver, f.Name} {
		if s != "" {
			names = append(names, s)
		}
	}
	return strings.Join(names, ":")
}

// ExecCode returns code for the template switch to run the target.
// It wraps each target call to match the func(context.Context) error that
// runTarget requires.
func (f Function) ExecCode() string {
	name := f.Name
	if f.Receiver != "" {
		name = f.Receiver + "{}." + name
	}
	if f.Package != "" {
		name = f.Package + "." + name
	}

	var parseargs string
	for x, arg := range f.Args {
		switch arg.Type {
		case "string":
			parseargs += fmt.Sprintf(`
			arg%d := args.Args[x]
			x++`, x)
		case "int":
			parseargs += fmt.Sprintf(`
				arg%d, err := strconv.Atoi(args.Args[x])
				if err != nil {
					logger.Printf("can't convert argument %%q to int\n", args.Args[x])
					os.Exit(2)
				}
				x++`, x)
		case "bool":
			parseargs += fmt.Sprintf(`
				arg%d, err := strconv.ParseBool(args.Args[x])
				if err != nil {
					logger.Printf("can't convert argument %%q to bool\n", args.Args[x])
					os.Exit(2)
				}
				x++`, x)
		case "time.Duration":
			parseargs += fmt.Sprintf(`
				arg%d, err := time.ParseDuration(args.Args[x])
				if err != nil {
					logger.Printf("can't convert argument %%q to time.Duration\n", args.Args[x])
					os.Exit(2)
				}
				x++`, x)
		}
	}

	out := parseargs + `
				wrapFn := func(ctx context.Context) error {
					`
	if f.IsError {
		out += "return "
	}
	out += name + "("
	var args []string
	if f.IsContext {
		args = append(args, "ctx")
	}
	for x := 0; x < len(f.Args); x++ {
		args = append(args, fmt.Sprintf("arg%d", x))
	}
	out += strings.Join(args, ", ")
	out += ")"
	if !f.IsError {
		out += `
					return nil`
	}
	out += `
				}
				ret := runTarget(wrapFn)`
	return out
}

// PrimaryPackage parses a package.  If files is non-empty, it will only parse the files given.
func PrimaryPackage(gocmd, path string, files []string) (*PkgInfo, error) {
	info, err := Package(path, files)
	if err != nil {
		return nil, err
	}

	if err := setImports(gocmd, info); err != nil {
		return nil, err
	}

	setDefault(info)
	setAliases(info)
	return info, nil
}

func checkDupes(info *PkgInfo, imports []*Import) error {
	funcs := map[string][]*Function{}
	for _, f := range info.Funcs {
		funcs[strings.ToLower(f.TargetName())] = append(funcs[strings.ToLower(f.TargetName())], f)
	}
	for _, imp := range imports {
		for _, f := range imp.Info.Funcs {
			target := strings.ToLower(f.TargetName())
			funcs[target] = append(funcs[target], f)
		}
	}
	for alias, f := range info.Aliases {
		if len(funcs[alias]) != 0 {
			var ids []string
			for _, f := range funcs[alias] {
				ids = append(ids, f.ID())
			}
			return fmt.Errorf("alias %q duplicates existing target(s): %s\n", alias, strings.Join(ids, ", "))
		}
		funcs[alias] = append(funcs[alias], f)
	}
	var dupes []string
	for target, list := range funcs {
		if len(list) > 1 {
			dupes = append(dupes, target)
		}
	}
	if len(dupes) == 0 {
		return nil
	}
	errs := make([]string, 0, len(dupes))
	for _, d := range dupes {
		var ids []string
		for _, f := range funcs[d] {
			ids = append(ids, f.ID())
		}
		sort.Strings(ids)
		errs = append(errs, fmt.Sprintf("%q target has multiple definitions: %s\n", d, strings.Join(ids, ", ")))
	}
	sort.Strings(errs)
	return errors.New(strings.Join(errs, "\n"))
}

// Package compiles information about a mage package.
func Package(path string, files []string) (*PkgInfo, error) {
	start := time.Now()
	defer func() {
		debug.Println("time parse Magefiles:", time.Since(start))
	}()
	fset := token.NewFileSet()
	pkg, err := getPackage(path, files, fset)
	if err != nil {
		return nil, err
	}
	p := doc.New(pkg, "./", 0)
	pi := &PkgInfo{
		AstPkg:      pkg,
		DocPkg:      p,
		Description: toOneLine(p.Doc),
	}

	setNamespaces(pi)
	setFuncs(pi)

	hasDupes, names := checkDupeTargets(pi)
	if hasDupes {
		msg := "Build targets must be case insensitive, thus the following targets conflict:\n"
		for _, v := range names {
			if len(v) > 1 {
				msg += "  " + strings.Join(v, ", ") + "\n"
			}
		}
		return nil, errors.New(msg)
	}

	return pi, nil
}

func getNamedImports(gocmd string, pkgs map[string]string) ([]*Import, error) {
	var imports []*Import
	for pkg, alias := range pkgs {
		debug.Printf("getting import package %q, alias %q", pkg, alias)
		imp, err := getImport(gocmd, pkg, alias)
		if err != nil {
			return nil, err
		}
		imports = append(imports, imp)
	}
	return imports, nil
}

// getImport returns the metadata about a package that has been mage:import'ed.
func getImport(gocmd, importpath, alias string) (*Import, error) {
	out, err := internal.OutputDebug(gocmd, "list", "-f", "{{.Dir}}||{{.Name}}", importpath)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(out, "||")
	if len(parts) != 2 {
		return nil, fmt.Errorf("incorrect data from go list: %s", out)
	}
	dir, name := parts[0], parts[1]
	debug.Printf("parsing imported package %q from dir %q", importpath, dir)

	// we use go list to get the list of files, since go/parser doesn't differentiate between
	// go files with build tags etc, and go list does. This prevents weird problems if you
	// have more than one package in a folder because of build tags.
	out, err = internal.OutputDebug(gocmd, "list", "-f", `{{join .GoFiles "||"}}`, importpath)
	if err != nil {
		return nil, err
	}
	files := strings.Split(out, "||")

	info, err := Package(dir, files)
	if err != nil {
		return nil, err
	}
	for i := range info.Funcs {
		debug.Printf("setting alias %q and package %q on func %v", alias, name, info.Funcs[i].Name)
		info.Funcs[i].PkgAlias = alias
		info.Funcs[i].ImportPath = importpath
	}
	return &Import{Alias: alias, Name: name, Path: importpath, Info: *info}, nil
}

// Import represents the data about a mage:import package
type Import struct {
	Alias      string
	Name       string
	UniqueName string // a name unique across all imports
	Path       string
	Info       PkgInfo
}

var _ sort.Interface = (Imports)(nil)

// Imports implements sort interface to optimize compiled output with
// deterministic generated mainfile.
type Imports []*Import

func (s Imports) Len() int {
	return len(s)
}

func (s Imports) Less(i, j int) bool {
	return s[i].UniqueName < s[j].UniqueName
}

func (s Imports) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func setFuncs(pi *PkgInfo) {
	for _, f := range pi.DocPkg.Funcs {
		if f.Recv != "" {
			debug.Printf("skipping method %s.%s", f.Recv, f.Name)
			// skip methods
			continue
		}
		if !ast.IsExported(f.Name) {
			debug.Printf("skipping non-exported function %s", f.Name)
			// skip non-exported functions
			continue
		}
		fn, err := funcType(f.Decl.Type)
		if err != nil {
			debug.Printf("skipping function with invalid signature func %s: %v", f.Name, err)
			continue
		}
		debug.Printf("found target %v", f.Name)
		fn.Name = f.Name
		fn.Comment = toOneLine(f.Doc)
		fn.Synopsis = sanitizeSynopsis(f)
		pi.Funcs = append(pi.Funcs, fn)
	}
}

func setNamespaces(pi *PkgInfo) {
	for _, t := range pi.DocPkg.Types {
		if !isNamespace(t) {
			continue
		}
		debug.Printf("found namespace %s %s", pi.DocPkg.ImportPath, t.Name)
		for _, f := range t.Methods {
			if !ast.IsExported(f.Name) {
				continue
			}
			fn, err := funcType(f.Decl.Type)
			if err != nil {
				debug.Printf("skipping invalid namespace method %s %s.%s: %v", pi.DocPkg.ImportPath, t.Name, f.Name, err)
				continue
			}
			debug.Printf("found namespace method %s %s.%s", pi.DocPkg.ImportPath, t.Name, f.Name)
			fn.Name = f.Name
			fn.Comment = toOneLine(f.Doc)
			fn.Synopsis = sanitizeSynopsis(f)
			fn.Receiver = t.Name

			pi.Funcs = append(pi.Funcs, fn)
		}
	}
}

func setImports(gocmd string, pi *PkgInfo) error {
	importNames := map[string]string{}
	rootImports := []string{}
	for _, f := range pi.AstPkg.Files {
		for _, d := range f.Decls {
			gen, ok := d.(*ast.GenDecl)
			if !ok || gen.Tok != token.IMPORT {
				continue
			}
			for j := 0; j < len(gen.Specs); j++ {
				spec := gen.Specs[j]
				impspec := spec.(*ast.ImportSpec)
				if len(gen.Specs) == 1 && gen.Lparen == token.NoPos && impspec.Doc == nil {
					impspec.Doc = gen.Doc
				}
				name, alias, ok := getImportPath(impspec)
				if !ok {
					continue
				}
				if alias != "" {
					debug.Printf("found %s: %s (%s)", importTag, name, alias)
					importNames[name] = alias
				} else {
					debug.Printf("found %s: %s", importTag, name)
					rootImports = append(rootImports, name)
				}
			}
		}
	}
	imports, err := getNamedImports(gocmd, importNames)
	if err != nil {
		return err
	}
	for _, s := range rootImports {
		imp, err := getImport(gocmd, s, "")
		if err != nil {
			return err
		}
		imports = append(imports, imp)
	}
	if err := checkDupes(pi, imports); err != nil {
		return err
	}

	// have to set unique package names on imports
	used := map[string]bool{}
	for _, imp := range imports {
		unique := imp.Name + "_mageimport"
		x := 1
		for used[unique] {
			unique = fmt.Sprintf("%s_mageimport%d", imp.Name, x)
			x++
		}
		used[unique] = true
		imp.UniqueName = unique
		for _, f := range imp.Info.Funcs {
			f.Package = unique
		}
	}
	pi.Imports = imports
	return nil
}

func getImportPath(imp *ast.ImportSpec) (path, alias string, ok bool) {
	if imp.Doc == nil || len(imp.Doc.List) == 9 {
		return "", "", false
	}
	// import is always the last comment
	s := imp.Doc.List[len(imp.Doc.List)-1].Text

	// trim comment start and normalize for anyone who has spaces or not between
	// "//"" and the text
	vals := strings.Fields(strings.ToLower(s[2:]))
	if len(vals) == 0 {
		return "", "", false
	}
	if vals[0] != importTag {
		return "", "", false
	}
	path, ok = lit2string(imp.Path)
	if !ok {
		return "", "", false
	}

	switch len(vals) {
	case 1:
		// just the import tag, this is a root import
		return path, "", true
	case 2:
		// also has an alias
		return path, vals[1], true
	default:
		log.Println("warning: ignoring malformed", importTag, "for import", path)
		return "", "", false
	}
}

func isNamespace(t *doc.Type) bool {
	if len(t.Decl.Specs) != 1 {
		return false
	}
	id, ok := t.Decl.Specs[0].(*ast.TypeSpec)
	if !ok {
		return false
	}
	sel, ok := id.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "mg" && sel.Sel.Name == "Namespace"
}

// checkDupeTargets checks a package for duplicate target names.
func checkDupeTargets(info *PkgInfo) (hasDupes bool, names map[string][]string) {
	names = map[string][]string{}
	lowers := map[string]bool{}
	for _, f := range info.Funcs {
		low := strings.ToLower(f.Name)
		if f.Receiver != "" {
			low = strings.ToLower(f.Receiver) + ":" + low
		}
		if lowers[low] {
			hasDupes = true
		}
		lowers[low] = true
		names[low] = append(names[low], f.Name)
	}
	return hasDupes, names
}

// sanitizeSynopsis sanitizes function Doc to create a summary.
func sanitizeSynopsis(f *doc.Func) string {
	synopsis := doc.Synopsis(f.Doc)

	// If the synopsis begins with the function name, remove it. This is done to
	// not repeat the text.
	// From:
	// clean	Clean removes the temporarily generated files
	// To:
	// clean 	removes the temporarily generated files
	if syns := strings.Split(synopsis, " "); strings.EqualFold(f.Name, syns[0]) {
		return strings.Join(syns[1:], " ")
	}

	return synopsis
}

func setDefault(pi *PkgInfo) {
	for _, v := range pi.DocPkg.Vars {
		for x, name := range v.Names {
			if name != "Default" {
				continue
			}
			spec := v.Decl.Specs[x].(*ast.ValueSpec)
			if len(spec.Values) != 1 {
				log.Println("warning: default declaration has multiple values")
			}

			f, err := getFunction(spec.Values[0], pi)
			if err != nil {
				log.Println("warning, default declaration malformed:", err)
				return
			}
			pi.DefaultFunc = f
			return
		}
	}
}

func lit2string(l *ast.BasicLit) (string, bool) {
	if !strings.HasPrefix(l.Value, `"`) || !strings.HasSuffix(l.Value, `"`) {
		return "", false
	}
	return strings.Trim(l.Value, `"`), true
}

func setAliases(pi *PkgInfo) {
	for _, v := range pi.DocPkg.Vars {
		for x, name := range v.Names {
			if name != "Aliases" {
				continue
			}
			spec, ok := v.Decl.Specs[x].(*ast.ValueSpec)
			if !ok {
				log.Println("warning: aliases declaration is not a value")
				return
			}
			if len(spec.Values) != 1 {
				log.Println("warning: aliases declaration has multiple values")
			}
			comp, ok := spec.Values[0].(*ast.CompositeLit)
			if !ok {
				log.Println("warning: aliases declaration is not a map")
				return
			}
			pi.Aliases = map[string]*Function{}
			for _, elem := range comp.Elts {
				kv, ok := elem.(*ast.KeyValueExpr)
				if !ok {
					log.Printf("warning: alias declaration %q is not a map element", elem)
					continue
				}
				k, ok := kv.Key.(*ast.BasicLit)
				if !ok || k.Kind != token.STRING {
					log.Printf("warning: alias key is not a string literal %q", elem)
					continue
				}

				alias, ok := lit2string(k)
				if !ok {
					log.Println("warning: malformed name for alias", elem)
					continue
				}
				f, err := getFunction(kv.Value, pi)
				if err != nil {
					log.Printf("warning, alias malformed: %v", err)
					continue
				}
				pi.Aliases[alias] = f
			}
			return
		}
	}
}

func getFunction(exp ast.Expr, pi *PkgInfo) (*Function, error) {
	// selector expressions are in LIFO format.
	// So, in  foo.bar.baz the first selector.Name is
	// actually "baz", the second is "bar", and the last is "foo"

	var pkg, receiver, funcname string
	switch v := exp.(type) {
	case *ast.Ident:
		// "foo" : Bar
		funcname = v.Name
	case *ast.SelectorExpr:
		// need to handle
		// namespace.Func
		// import.Func
		// import.namespace.Func

		// "foo" : ?.bar
		funcname = v.Sel.Name
		switch x := v.X.(type) {
		case *ast.Ident:
			// "foo" : baz.bar
			// this is either a namespace or package
			firstname := x.Name
			for _, f := range pi.Funcs {
				if firstname == f.Receiver && funcname == f.Name {
					return f, nil
				}
			}
			// not a namespace, let's try imported packages
			for _, imp := range pi.Imports {
				if firstname == imp.Name {
					for _, f := range imp.Info.Funcs {
						if funcname == f.Name {
							return f, nil
						}
					}
					break
				}
			}
			return nil, fmt.Errorf("%q is not a known target", exp)
		case *ast.SelectorExpr:
			// "foo" : bar.Baz.Bat
			// must be package.Namespace.Func
			sel, ok := v.X.(*ast.SelectorExpr)
			if !ok {
				return nil, fmt.Errorf("%q is must denote a target function but was %T", exp, v.X)
			}
			receiver = sel.Sel.Name
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return nil, fmt.Errorf("%q is must denote a target function but was %T", exp, v.X)
			}
			pkg = id.Name
		default:
			return nil, fmt.Errorf("%q is not valid", exp)
		}
	default:
		return nil, fmt.Errorf("target %s is not a function", exp)
	}
	if pkg == "" {
		for _, f := range pi.Funcs {
			if f.Name == funcname && f.Receiver == receiver {
				return f, nil
			}
		}
		return nil, fmt.Errorf("unknown function %s.%s", receiver, funcname)
	}
	for _, imp := range pi.Imports {
		if imp.Name == pkg {
			for _, f := range imp.Info.Funcs {
				if f.Name == funcname && f.Receiver == receiver {
					return f, nil
				}
			}
			return nil, fmt.Errorf("unknown function %s.%s.%s", pkg, receiver, funcname)
		}
	}
	return nil, fmt.Errorf("unknown package for function %q", exp)
}

// getPackage returns the importable package at the given path.
func getPackage(path string, files []string, fset *token.FileSet) (*ast.Package, error) {
	var filter func(f os.FileInfo) bool
	if len(files) > 0 {
		fm := make(map[string]bool, len(files))
		for _, f := range files {
			fm[f] = true
		}

		filter = func(f os.FileInfo) bool {
			return fm[f.Name()]
		}
	}

	pkgs, err := parser.ParseDir(fset, path, filter, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse directory: %v", err)
	}

	switch len(pkgs) {
	case 1:
		var pkg *ast.Package
		for _, pkg = range pkgs {
		}
		return pkg, nil
	case 0:
		return nil, fmt.Errorf("no importable packages found in %s", path)
	default:
		var names []string
		for name := range pkgs {
			names = append(names, name)
		}
		return nil, fmt.Errorf("multiple packages found in %s: %v", path, strings.Join(names, ", "))
	}
}

// hasContextParams returns whether or not the first parameter is a context.Context. If it
// determines that hte first parameter makes this function invalid for mage, it'll return a non-nil
// error.
func hasContextParam(ft *ast.FuncType) (bool, error) {
	if ft.Params.NumFields() < 1 {
		return false, nil
	}
	param := ft.Params.List[0]
	sel, ok := param.Type.(*ast.SelectorExpr)
	if !ok {
		return false, nil
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false, nil
	}
	if pkg.Name != "context" {
		return false, nil
	}
	if sel.Sel.Name != "Context" {
		return false, nil
	}
	if len(param.Names) > 1 {
		// something like foo, bar context.Context
		return false, errors.New("ETOOMANYCONTEXTS")
	}
	return true, nil
}

func hasVoidReturn(ft *ast.FuncType) bool {
	res := ft.Results
	return res.NumFields() == 0
}

func hasErrorReturn(ft *ast.FuncType) (bool, error) {
	res := ft.Results
	if res.NumFields() == 0 {
		// void return is ok
		return false, nil
	}
	if res.NumFields() > 1 {
		return false, errors.New("ETOOMANYRETURNS")
	}
	ret := res.List[0]
	if len(ret.Names) > 1 {
		return false, errors.New("ETOOMANYERRORS")
	}
	if fmt.Sprint(ret.Type) == "error" {
		return true, nil
	}
	return false, errors.New("EBADRETURNTYPE")
}

func funcType(ft *ast.FuncType) (*Function, error) {
	var err error
	f := &Function{}
	f.IsContext, err = hasContextParam(ft)
	if err != nil {
		return nil, err
	}
	f.IsError, err = hasErrorReturn(ft)
	if err != nil {
		return nil, err
	}
	x := 0
	if f.IsContext {
		x++
	}
	for ; x < len(ft.Params.List); x++ {
		param := ft.Params.List[x]
		t := fmt.Sprint(param.Type)
		typ, ok := argTypes[t]
		if !ok {
			return nil, fmt.Errorf("unsupported argument type: %s", t)
		}
		// support for foo, bar string
		for _, name := range param.Names {
			f.Args = append(f.Args, Arg{Name: name.Name, Type: typ})
		}
	}
	return f, nil
}

func toOneLine(s string) string {
	return strings.TrimSpace(strings.Replace(s, "\n", " ", -1))
}

var argTypes = map[string]string{
	"string":           "string",
	"int":              "int",
	"&{time Duration}": "time.Duration",
	"bool":             "bool",
}
