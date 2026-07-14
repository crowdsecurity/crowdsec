package modules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDatasourcesDoNotCloseSharedOutputChannel statically checks every
// datasource module for `close(out)` inside a Stream() or StreamingAcquisition()
// method. `out` is the pipeline output channel shared across every configured
// datasource (see acquisition.StartAcquisition); it is owned by the acquisition
// orchestrator, not by any individual datasource, so a datasource closing it
// races with any other datasource still sending on it and panics with "send on
// closed channel" (this happened in production with the syslog datasource).
//
// This is independent of any one datasource and covers every module directory
// under pkg/acquisition/modules automatically, including future ones, without
// needing to configure or run any of them.
func TestDatasourcesDoNotCloseSharedOutputChannel(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	modulesDir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(modulesDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		moduleDir := filepath.Join(modulesDir, entry.Name())

		moduleFiles, err := os.ReadDir(moduleDir)
		require.NoError(t, err, "reading module %s", entry.Name())

		fset := token.NewFileSet()

		for _, moduleFile := range moduleFiles {
			if moduleFile.IsDir() || filepath.Ext(moduleFile.Name()) != ".go" {
				continue
			}

			path := filepath.Join(moduleDir, moduleFile.Name())

			file, err := parser.ParseFile(fset, path, nil, 0)
			require.NoError(t, err, "parsing %s", path)

			checkFileDoesNotCloseOut(t, fset, entry.Name(), path, file)
		}
	}
}

// checkFileDoesNotCloseOut walks a single file's AST for Stream/StreamingAcquisition
// method declarations and fails if their body contains close(out).
func checkFileDoesNotCloseOut(t *testing.T, fset *token.FileSet, module string, path string, file *ast.File) {
	t.Helper()

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		if fn.Name.Name != "Stream" && fn.Name.Name != "StreamingAcquisition" {
			continue
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "close" || len(call.Args) != 1 {
				return true
			}

			arg, ok := call.Args[0].(*ast.Ident)
			if ok && arg.Name == "out" {
				t.Errorf(
					"%s: %s.%s must not close(out) -- it is the shared acquisition "+
						"output channel, owned by the orchestrator, not by this datasource (%s:%d)",
					module, module, fn.Name.Name, path, fset.Position(call.Pos()).Line,
				)
			}

			return true
		})
	}
}
