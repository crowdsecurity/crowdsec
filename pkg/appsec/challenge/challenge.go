package challenge

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"text/template"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/davecgh/go-spew/spew"
	esbuildapi "github.com/evanw/esbuild/pkg/api"
)

const ChallengeJSPath = "/crowdsec-internal/challenge/challenge.js"
const ChallengeSubmitPath = "/crowdsec-internal/challenge/submit"
const ChallengeCookieName = "__crowdsec_challenge"

//go:embed js/src/*
var jsFS embed.FS

//go:embed challenge.html.tmpl
var htmlTemplate string

const encryptionKey = "foobarlol42"

func BuildFingerprintScript() (string, error) {
	embeddedFSPlugin := esbuildapi.Plugin{
		Name: "embedded-fs",
		Setup: func(build esbuildapi.PluginBuild) {
			build.OnResolve(esbuildapi.OnResolveOptions{Filter: ".*"}, func(args esbuildapi.OnResolveArgs) (esbuildapi.OnResolveResult, error) {
				// Let esbuild handle remote/absolute URLs.
				if strings.HasPrefix(args.Path, "http://") || strings.HasPrefix(args.Path, "https://") || strings.HasPrefix(args.Path, "/") {
					return esbuildapi.OnResolveResult{}, nil
				}

				basePath := "js/src"
				if args.Importer != "" {
					basePath = path.Dir(args.Importer)
				}

				resolved, loader, err := resolveEmbeddedPath(basePath, args.Path)
				if err != nil {
					return esbuildapi.OnResolveResult{}, err
				}

				return esbuildapi.OnResolveResult{
					Path:       resolved,
					Namespace:  "embedded",
					PluginData: loader,
				}, nil
			})

			build.OnLoad(esbuildapi.OnLoadOptions{Filter: ".*", Namespace: "embedded"}, func(args esbuildapi.OnLoadArgs) (esbuildapi.OnLoadResult, error) {
				data, err := fs.ReadFile(jsFS, args.Path)
				if err != nil {
					return esbuildapi.OnLoadResult{}, err
				}

				contents := string(data)
				loader, ok := args.PluginData.(esbuildapi.Loader)
				if !ok {
					loader = loaderFromExt(args.Path)
				}

				return esbuildapi.OnLoadResult{
					Contents:   &contents,
					Loader:     loader,
					ResolveDir: path.Dir(args.Path),
				}, nil
			})
		},
	}

	result := esbuildapi.Build(esbuildapi.BuildOptions{
		EntryPoints:       []string{"js/src/index.ts"},
		Bundle:            true,
		Write:             false,
		MinifyWhitespace:  true,
		MinifyIdentifiers: true,
		MinifySyntax:      true,
		Sourcemap:         esbuildapi.SourceMapNone,
		Define: map[string]string{
			"__FP_ENCRYPTION_KEY__": fmt.Sprintf("\"%s\"", encryptionKey),
		},
		Plugins:  []esbuildapi.Plugin{embeddedFSPlugin},
		Format:   esbuildapi.FormatESModule,
		Target:   esbuildapi.ES2015,
		Platform: esbuildapi.PlatformBrowser,
	})

	if len(result.Errors) > 0 {
		return "", fmt.Errorf("build failed with errors: %v", result.Errors)
	}

	return string(result.OutputFiles[0].Contents), nil
}

// resolveEmbeddedPath emulates esbuild's relative resolution inside the embedded FS.
func resolveEmbeddedPath(basePath, importPath string) (string, esbuildapi.Loader, error) {
	var candidate string

	if strings.HasPrefix(importPath, ".") {
		candidate = path.Clean(path.Join(basePath, importPath))
	} else {
		candidate = importPath
		if !fileExistsInEmbed(candidate) {
			// Treat bare specifiers as relative to the importer inside the embedded tree.
			candidate = path.Clean(path.Join(basePath, importPath))
		}
	}

	if fileExistsInEmbed(candidate) {
		loader := loaderFromExt(candidate)
		if loader != esbuildapi.LoaderDefault {
			return candidate, loader, nil
		}
	}

	// Try common extensions if none was provided.
	tryExts := []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json"}
	for _, ext := range tryExts {
		withExt := candidate + ext
		if fileExistsInEmbed(withExt) {
			return withExt, loaderFromExt(withExt), nil
		}

		// If we looked at a joined path, also consider index resolution (e.g., importing a folder).
		if strings.HasSuffix(candidate, "/index") {
			continue
		}
		withIndex := path.Join(candidate, "index"+ext)
		if fileExistsInEmbed(withIndex) {
			return withIndex, loaderFromExt(withIndex), nil
		}
	}

	return "", esbuildapi.LoaderDefault, fmt.Errorf("embedded file not found for import %q (from %q)", importPath, basePath)
}

func loaderFromExt(p string) esbuildapi.Loader {
	switch path.Ext(p) {
	case ".ts":
		return esbuildapi.LoaderTS
	case ".tsx":
		return esbuildapi.LoaderTSX
	case ".js":
		return esbuildapi.LoaderJS
	case ".jsx":
		return esbuildapi.LoaderJSX
	case ".mjs", ".cjs":
		return esbuildapi.LoaderJS
	case ".json":
		return esbuildapi.LoaderJSON
	case ".css":
		return esbuildapi.LoaderCSS
	default:
		return esbuildapi.LoaderDefault
	}
}

func fileExistsInEmbed(p string) bool {
	_, err := fs.Stat(jsFS, p)
	return err == nil
}

func GetChallengePage() (string, error) {
	/*scripts, err := buildFingerprintScript()
	if err != nil {
		return "", fmt.Errorf("failed to build fingerprinting script: %w", err)
	}

	spew.Dump(scripts)

	scriptContent := ""
	for _, content := range scripts {
		scriptContent += content
	}*/

	// We are using text/template instead of html/template because the data we send is pretty much hardcoded and trusted.
	// Using html/template would escape the JS code we are adding, making it unusable.
	templateObj, err := template.New("challenge").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse challenge template: %w", err)
	}

	var renderedPage strings.Builder

	templateObj.Execute(&renderedPage, map[string]string{
		//"FPScript": scriptContent,
	})
	return renderedPage.String(), nil
}

func ValidateChallengeResponse(request *http.Request, body []byte) (*cookie.AppsecCookie, error) {

	spew.Dump(string(body))

	c := cookie.NewAppsecCookie(ChallengeCookieName).HttpOnly().Path("/").SameSite("Lax").ExpiresIn(time.Hour).Value("test")
	if request.URL.Scheme == "https" {
		c = c.Secure()
	}
	return c, nil
}
