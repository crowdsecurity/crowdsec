package challenge

import (
	"crypto/sha256"
	"strings"
	"testing"

	esbuildapi "github.com/evanw/esbuild/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detector builds a module that reports one marker value, so a test can tell
// whose code ended up in the output.
func detector(name, marker string) Detector {
	return Detector{
		Name:   name,
		Source: "export function " + customDetectExport + "(fp) { fp.custom = fp.custom || {}; fp.custom.x = \"" + marker + "\"; }\n",
	}
}

// requireParses is the collision test as much as a sanity check: concatenating
// two modules that both declare `const CFG` is an early SyntaxError, so an
// assembly that still parses proves the scopes were separated.
func requireParses(t *testing.T, src string) {
	t.Helper()

	result := esbuildapi.Transform(src, esbuildapi.TransformOptions{Target: esbuildapi.ES2022})
	require.Empty(t, result.Errors, "assembled output does not parse")
}

// The Go constant has to agree with challenge.js and obfuscate.js like the
// others; see the comment on customSentinel.
func TestAssembleUsesTheSharedSentinel(t *testing.T) {
	assert.Equal(t, customSentinel, customDetectGlobal)
}

func TestAssembleCustomJS(t *testing.T) {
	tests := []struct {
		name      string
		detectors []Detector
		wantOK    []string // markers expected in the output
		wantRej   []string // dest_files expected to be rejected
		wantErr   string   // substring the first rejection must contain
	}{
		{
			name:      "single module",
			detectors: []Detector{detector("challenge/a.js", "A")},
			wantOK:    []string{"A"},
		},
		{
			// The case that is an early SyntaxError today, taking every
			// detector down with it.
			name: "same top-level names in two modules",
			detectors: []Detector{
				{Name: "challenge/a.js", Source: "const CFG = \"A\";\nfunction helper() { return CFG }\nexport function collectSignals(fp) { fp.custom = { x: helper() } }\n"},
				{Name: "challenge/b.js", Source: "const CFG = \"B\";\nfunction helper() { return CFG }\nexport function collectSignals(fp) { fp.custom.y = helper() }\n"},
			},
			wantOK: []string{"A", "B"},
		},
		{
			name: "missing export is rejected, the rest still build",
			detectors: []Detector{
				{Name: "challenge/bad.js", Source: "function collectSignals(fp) {}\n"},
				detector("challenge/good.js", "GOOD"),
			},
			wantOK:  []string{"GOOD"},
			wantRej: []string{"challenge/bad.js"},
			wantErr: customDetectExport,
		},
		{
			// The regression test for the bug this replaces: one unparseable
			// file used to cost every other detector its registration.
			name: "syntax error is rejected, the rest still build",
			detectors: []Detector{
				{Name: "challenge/bad.js", Source: "export function collectSignals(fp) {\n"},
				detector("challenge/good.js", "GOOD"),
			},
			wantOK:  []string{"GOOD"},
			wantRej: []string{"challenge/bad.js"},
			wantErr: "challenge/bad.js:",
		},
		{
			name:      "relative import is rejected",
			detectors: []Detector{{Name: "challenge/a.js", Source: "import u from \"./util.js\";\nexport function collectSignals(fp) { u }\n"}},
			wantRej:   []string{"challenge/a.js"},
			wantErr:   "self-contained",
		},
		{
			name:      "bare import is rejected",
			detectors: []Detector{{Name: "challenge/a.js", Source: "import \"lodash\";\nexport function collectSignals(fp) {}\n"}},
			wantRej:   []string{"challenge/a.js"},
			wantErr:   "self-contained",
		},
		{
			name:      "dynamic import of a literal is rejected",
			detectors: []Detector{{Name: "challenge/a.js", Source: "export function collectSignals(fp) { import(\"./x.js\") }\n"}},
			wantRej:   []string{"challenge/a.js"},
			wantErr:   "self-contained",
		},
		{
			name:      "require of a literal is rejected",
			detectors: []Detector{{Name: "challenge/a.js", Source: "export function collectSignals(fp) { require(\"x\") }\n"}},
			wantRej:   []string{"challenge/a.js"},
			wantErr:   "self-contained",
		},
		{
			// The internal scheme is not a back door into the resolver.
			name:      "importing the internal scheme is rejected",
			detectors: []Detector{{Name: "challenge/a.js", Source: "import \"" + detectorSpecifier + "\";\nexport function collectSignals(fp) {}\n"}},
			wantRej:   []string{"challenge/a.js"},
			wantErr:   "self-contained",
		},
		{
			// Rejected at parse time only because the output format is IIFE;
			// pins that the build format cannot drift.
			name:      "top-level await is rejected",
			detectors: []Detector{{Name: "challenge/a.js", Source: "await 1;\nexport function collectSignals(fp) {}\n"}},
			wantRej:   []string{"challenge/a.js"},
			wantErr:   "await",
		},
		{
			// dest_file is echoed into the output as a comment, so it may not
			// carry anything that closes one.
			name:      "unusable dest_file is rejected",
			detectors: []Detector{detector("challenge/a.js\";evil();//", "A")},
			wantRej:   []string{"challenge/a.js\";evil();//"},
			wantErr:   "unusable dest_file",
		},
		{
			name:      "every module rejected yields nothing",
			detectors: []Detector{{Name: "challenge/a.js", Source: "syntax error(\n"}},
			wantRej:   []string{"challenge/a.js"},
		},
		{
			name: "no detectors",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, rejected := AssembleCustomJS(tc.detectors)

			names := make([]string, 0, len(rejected))
			for _, r := range rejected {
				names = append(names, r.Name)
			}

			assert.Equal(t, tc.wantRej, nilIfEmpty(names))

			if tc.wantErr != "" {
				require.NotEmpty(t, rejected)
				assert.Contains(t, rejected[0].Err.Error(), tc.wantErr)
			}

			if len(tc.wantOK) == 0 {
				assert.Empty(t, out)
				return
			}

			requireParses(t, out)
			assert.Contains(t, out, customDetectGlobal)

			for _, marker := range tc.wantOK {
				assert.Contains(t, out, "\""+marker+"\"")
			}
		})
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}

	return s
}

// A non-literal specifier never reaches the resolver, so esbuild only warns and
// the call survives to throw in the browser. Pinned so nobody "fixes" it by
// accident; documented in custom_js.md.
func TestAssembleKeepsModuleWithNonLiteralImport(t *testing.T) {
	out, rejected := AssembleCustomJS([]Detector{
		{Name: "challenge/a.js", Source: "export function collectSignals(fp) { import(fp.where) }\n"},
	})

	assert.Empty(t, rejected)
	assert.Contains(t, out, customDetectGlobal)
}

// A module that throws while loading must cost only its own registration.
func TestAssembleIsolatesLoadTimeThrow(t *testing.T) {
	out, rejected := AssembleCustomJS([]Detector{
		{Name: "challenge/throws.js", Source: "throw new Error(\"boom\");\nexport function collectSignals(fp) {}\n"},
		detector("challenge/good.js", "GOOD"),
	})

	require.Empty(t, rejected)
	requireParses(t, out)

	assert.Equal(t, 2, strings.Count(out, "try{"), "each module needs its own catch")
	assert.Less(t, strings.Index(out, "boom"), strings.Index(out, "}catch(e){}"),
		"the throw must sit inside the first module's catch")
}

func TestAssemblePreservesOrder(t *testing.T) {
	out, rejected := AssembleCustomJS([]Detector{
		detector("challenge/a.js", "FIRST"),
		detector("challenge/b.js", "SECOND"),
		detector("challenge/c.js", "THIRD"),
	})

	require.Empty(t, rejected)
	assert.Less(t, strings.Index(out, "FIRST"), strings.Index(out, "SECOND"))
	assert.Less(t, strings.Index(out, "SECOND"), strings.Index(out, "THIRD"))
}

// The output digest is the cache key on an hour-cached URL, so identical input
// has to produce identical bytes across runs. Looped because esbuild parses on
// several goroutines.
func TestAssembleIsDeterministic(t *testing.T) {
	detectors := []Detector{
		detector("challenge/a.js", "A"),
		detector("challenge/b.js", "B"),
		detector("challenge/c.js", "C"),
	}

	want, rejected := AssembleCustomJS(detectors)
	require.Empty(t, rejected)
	require.NotEmpty(t, want)

	wantSum := sha256.Sum256([]byte(want))

	for range 20 {
		got, _ := AssembleCustomJS(detectors)
		require.Equal(t, want, got)
		require.Equal(t, wantSum, sha256.Sum256([]byte(got)))
	}
}

// fpscanner's CDP check needs console.log to keep its side effect; the same
// goes for a hub detector. Guards against anyone adding Drop: DropConsole.
func TestAssembleKeepsConsoleCalls(t *testing.T) {
	out, rejected := AssembleCustomJS([]Detector{
		{Name: "challenge/a.js", Source: "export function collectSignals(fp) { try { null.x } catch (e) { console.log(e) } }\n"},
	})

	require.Empty(t, rejected)
	assert.Contains(t, out, "console.log")
}

// The response carries no charset, so anything non-ASCII has to be escaped or
// the browser may decode it wrong.
func TestAssembleOutputIsASCII(t *testing.T) {
	out, rejected := AssembleCustomJS([]Detector{
		{Name: "challenge/a.js", Source: "export function collectSignals(fp) { fp.custom = { s: \"café\" } }\n"},
	})

	require.Empty(t, rejected)

	for i := range len(out) {
		require.Less(t, out[i], byte(0x80), "non-ASCII byte at offset %d", i)
	}
}

// The bundler's CommonJS interop helpers have no business in a detection
// script; their presence would mean a module was misclassified.
func TestAssembleLeaksNoBundlerRuntime(t *testing.T) {
	out, rejected := AssembleCustomJS([]Detector{detector("challenge/a.js", "A")})

	require.Empty(t, rejected)
	assert.NotContains(t, out, "__toESM")
	assert.NotContains(t, out, "__commonJS")
}
