// customjs_assemble.go compiles the detection modules an appsec-config ships
// through the hub into the script served at ChallengeCustomJSPath.
//
// Each module is built and wrapped in its own IIFE, to limit blast zone if a
// a detector fails to parse etc.

package challenge

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	esbuildapi "github.com/evanw/esbuild/pkg/api"
)

// customDetectGlobal is the array challenge.js drains after fpscanner runs.
const customDetectGlobal = "__CSEC_CUSTOM_DETECT_v1__"

// customDetectExport is the one symbol a detection module has to expose.
const customDetectExport = "collectSignals"

const (
	// detectorNamespace keeps every module out of esbuild's "file" namespace
	detectorNamespace = "csdet"

	// detectorSpecifier is a fixed literal rather than the dest_file
	detectorSpecifier = detectorNamespace + ":d"
)

// moduleMarker forces esbuild to read the file as an ES module. Without an
// import or export of its own a file is taken for CommonJS, and asking it for a
// named export then yields undefined instead of an error.
const moduleMarker = "\n;export {};\n"

// safeDetectorName bounds what can reach esbuild's module path, which with
// minification off is echoed into the output as a `// csdet:<name>` comment.
var safeDetectorName = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// Detector is one hub-shipped detection module. Name is the dest_file it was
// installed as, and is what build diagnostics are attributed to.
type Detector struct {
	Name   string
	Source string
}

// DetectorError names a detector that was dropped, and why.
type DetectorError struct {
	Name string
	Err  error
}

func (e DetectorError) Error() string {
	return fmt.Sprintf("custom detection %s: %s", e.Name, e.Err)
}

func (e DetectorError) Unwrap() error {
	return e.Err
}

// AssembleCustomJS compiles each detector in slice,
// rejected holds the rest.
func AssembleCustomJS(detectors []Detector) (string, []DetectorError) {
	var (
		fragments []string
		rejected  []DetectorError
	)

	for _, d := range detectors {
		fragment, err := buildDetector(d)
		if err != nil {
			rejected = append(rejected, DetectorError{Name: d.Name, Err: err})
			continue
		}

		fragments = append(fragments, fragment)
	}

	return strings.Join(fragments, ""), rejected
}

// buildDetector turns one ES module into a self-registering IIFE (self-executing function wrapper)
func buildDetector(d Detector) (string, error) {
	if !safeDetectorName.MatchString(d.Name) {
		return "", fmt.Errorf("unusable dest_file %q: expected only letters, digits and %q", d.Name, "._/-")
	}

	result := esbuildapi.Build(esbuildapi.BuildOptions{
		Stdin: &esbuildapi.StdinOptions{
			Contents: detectorEntry(),
			Loader:   esbuildapi.LoaderJS,
			// ResolveDir stays empty: the plugin answers every specifier.
		},
		Plugins: []esbuildapi.Plugin{detectorFS(d)},
		Bundle:  true,
		Write:   false,
		Format:  esbuildapi.FormatIIFE,
		// A detector that throws while loading must not break the rest.
		Banner:   map[string]string{"js": "try{"},
		Footer:   map[string]string{"js": "}catch(e){}\n"},
		Platform: esbuildapi.PlatformBrowser,
		Target:   esbuildapi.ES2022,
		// we remove all minification and such in case we need to do some weird js sheningans
		TreeShaking: esbuildapi.TreeShakingFalse,
		Sourcemap:   esbuildapi.SourceMapNone,
		LogLevel:    esbuildapi.LogLevelSilent,
		LogLimit:    10,
	})

	if len(result.Errors) > 0 {
		return "", buildError(d.Name, result.Errors)
	}

	if len(result.OutputFiles) == 0 {
		return "", errors.New("esbuild returned no output")
	}

	return string(result.OutputFiles[0].Contents), nil
}

// detectorEntry registers the module's export. It mirrors the consumer's own
// guard in challenge.js, so junk left on the global cannot make push throw.
func detectorEntry() string {
	return fmt.Sprintf(`import { %s } from %q;

(function () {
  var g = globalThis;
  var h = g.%s;
  if (!Array.isArray(h)) {
    h = g.%s = [];
  }
  h.push(%s);
})();
`, customDetectExport, detectorSpecifier, customDetectGlobal, customDetectGlobal, customDetectExport)
}

// detectorFS serves the module from memory and refuses everything else, so a
// detector cannot pull in a second file, an npm package, or anything on disk.
func detectorFS(d Detector) esbuildapi.Plugin {
	return esbuildapi.Plugin{
		Name: "crowdsec-custom-detections",
		Setup: func(b esbuildapi.PluginBuild) {
			// Registered first: esbuild runs OnResolve callbacks in order and
			// stops at the one that returns a path.
			b.OnResolve(esbuildapi.OnResolveOptions{Filter: `^` + detectorNamespace + `:`},
				func(args esbuildapi.OnResolveArgs) (esbuildapi.OnResolveResult, error) {
					// Namespace is the importer's, so this is the module trying
					// to reach the internal scheme rather than the entry.
					if args.Namespace == detectorNamespace {
						return rejectImport(args), nil
					}

					// Resolving to the dest_file rather than the specifier is
					// what makes esbuild report errors against the file the
					// operator installed.
					return esbuildapi.OnResolveResult{Path: d.Name, Namespace: detectorNamespace}, nil
				})

			b.OnResolve(esbuildapi.OnResolveOptions{Filter: `.*`},
				func(args esbuildapi.OnResolveArgs) (esbuildapi.OnResolveResult, error) {
					return rejectImport(args), nil
				})

			b.OnLoad(esbuildapi.OnLoadOptions{Filter: `.*`, Namespace: detectorNamespace},
				func(_ esbuildapi.OnLoadArgs) (esbuildapi.OnLoadResult, error) {
					src := d.Source + moduleMarker
					return esbuildapi.OnLoadResult{Contents: &src, Loader: esbuildapi.LoaderJS}, nil
				})
		},
	}
}

// rejectImport leaves Location nil so esbuild fills in the import site, which
// points the operator at the offending line rather than at the entry.
func rejectImport(args esbuildapi.OnResolveArgs) esbuildapi.OnResolveResult {
	return esbuildapi.OnResolveResult{Errors: []esbuildapi.Message{{
		Text: fmt.Sprintf("cannot import %q: a detection module must be self-contained", args.Path),
	}}}
}

// buildError turns esbuild diagnostics into one line an operator can act on.
func buildError(name string, msgs []esbuildapi.Message) error {
	parts := make([]string, 0, len(msgs))

	for _, msg := range msgs {
		parts = append(parts, formatBuildMessage(name, msg))
	}

	return errors.New(strings.Join(parts, "; "))
}

func formatBuildMessage(name string, msg esbuildapi.Message) string {
	text := msg.Text

	// esbuild's own wording for this names the internal specifier and reads as
	// a bundler problem, which is not what the author needs to hear.
	if strings.Contains(text, "No matching export") && strings.Contains(text, customDetectExport) {
		text = fmt.Sprintf("must export a function named %s (see custom_js.md)", customDetectExport)
	}

	loc := msg.Location
	if loc == nil {
		return text
	}

	// The location is reported in the virtual namespace; the operator knows the
	// file by its dest_file.
	file := strings.TrimPrefix(loc.File, detectorNamespace+":")
	if file == "" || file == "<stdin>" {
		file = name
	}

	return fmt.Sprintf("%s:%d:%d: %s", file, loc.Line, loc.Column, text)
}
