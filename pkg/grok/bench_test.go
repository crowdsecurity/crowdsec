package grok

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Patterns and lines come from the sshd-logs and nginx-logs hub parsers. What matters here
// is the stage walk: a line is tried against every node of a stage and misses nearly all of
// them, so the miss path is the one that dominates.
var benchSSHPatterns = []string{
	`Failed %{WORD:method} for %{USERNAME:user} from %{IP:src_ip} port %{NUMBER:port} %{WORD:proto}`,
	`Disconnected from authenticating user %{USERNAME:user} %{IP:src_ip} port %{NUMBER:port} \[preauth\]`,
	`Connection closed by authenticating user %{USERNAME:user} %{IP:src_ip} port %{NUMBER:port} \[preauth\]`,
	`Invalid user %{USERNAME:user} from %{IP:src_ip} port %{NUMBER:port}`,
	`Unable to negotiate with %{IP:src_ip} port %{NUMBER:port}: no matching key exchange method found.`,
	`pam_unix\(sshd:auth\): authentication failure; logname= uid=%{NUMBER:uid} euid=%{NUMBER:euid} tty=ssh ruser= rhost=%{IP:src_ip}`,
	`Timeout before authentication for %{IP:src_ip} port %{NUMBER:port}`,
	`refused connect from %{DATA:host}\(%{IP:src_ip}\)`,
}

const benchUA = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) ` +
	`Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0 (Edition std-1) ` +
	`AlexaToolbar/alxg-3.3 BingPreview/1.0b YandexBot/3.0 SemrushBot/7~bl AhrefsBot/7.0`

const benchQuery = `?utm_source=newsletter&utm_medium=email&utm_campaign=spring_sale_2024&` +
	`ref=aff_12345&session=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855&` +
	`redirect=%2Fcheckout%2Fcart%3Fstep%3Dpayment&locale=en_US&currency=EUR&debug=false`

var benchCases = []struct {
	name    string
	pattern string
	line    string
}{
	// first node of the stage
	{"ssh/hit_first", benchSSHPatterns[0], "Failed password for root from 192.168.1.1 port 22 ssh2"},
	// last node of the stage
	{"ssh/hit_last", benchSSHPatterns[7], "refused connect from attacker(192.168.1.1)"},
	// the common case: nothing in the stage matches
	{"ssh/miss", benchSSHPatterns[0], "Accepted publickey for admin from 10.0.0.1 port 22 ssh2"},
	// long lines: the cost of both the engine and, later, the literal scan grows with the input
	{"http/hit", `%{COMBINEDAPACHELOG}`, `192.168.1.1 - - [20/Dec/2023:10:12:33 +0100] "GET /index.php` + benchQuery + ` HTTP/1.1" 200 4523 "https://example.com/landing" "` + benchUA + `"`},
	{"http/miss", `%{COMBINEDAPACHELOG}`, `192.168.1.1 - - 20/Dec/2023:10:12:33 +0100 GET /index.php` + benchQuery + ` HTTP/1.1 200 4523 https://example.com/landing ` + benchUA},
}

var benchEngines = []struct {
	name   string
	useRe2 bool
}{{"legacy", false}, {"re2", true}}

func benchCompile(b *testing.B, useRe2 bool, exprs ...string) []Pattern {
	b.Helper()

	h := NewBase()
	h.UseRe2 = useRe2

	out := make([]Pattern, 0, len(exprs))
	for _, expr := range exprs {
		p, err := h.Compile(expr)
		require.NoError(b, err, expr)
		out = append(out, p)
	}
	return out
}

// BenchmarkParse is the call path ParseInto replaces: Parse allocates a map, the caller
// copies it into the event and drops it. Compare against BenchmarkParseInto.
func BenchmarkParse(b *testing.B) {
	for _, engine := range benchEngines {
		for _, bc := range benchCases {
			b.Run(engine.name+"/"+bc.name, func(b *testing.B) {
				p := benchCompile(b, engine.useRe2, bc.pattern)[0]
				dst := make(map[string]string)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					for k, v := range p.Parse(bc.line) {
						dst[k] = v
					}
				}
			})
		}
	}
}

func BenchmarkParseInto(b *testing.B) {
	for _, engine := range benchEngines {
		for _, bc := range benchCases {
			b.Run(engine.name+"/"+bc.name, func(b *testing.B) {
				p := benchCompile(b, engine.useRe2, bc.pattern)[0]
				dst := make(map[string]string)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					p.ParseInto(bc.line, dst)
				}
			})
		}
	}
}

// BenchmarkStageWalk tries every node of a stage until one matches, which is where the cost
// of a miss gets multiplied.
func BenchmarkStageWalk(b *testing.B) {
	for _, engine := range benchEngines {
		for _, bc := range benchCases[:3] {
			b.Run("parse/"+engine.name+"/"+bc.name, func(b *testing.B) {
				pats := benchCompile(b, engine.useRe2, benchSSHPatterns...)
				dst := make(map[string]string)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					for _, p := range pats {
						m := p.Parse(bc.line)
						if len(m) == 0 {
							continue
						}
						for k, v := range m {
							dst[k] = v
						}
						break
					}
				}
			})

			b.Run("parse_into/"+engine.name+"/"+bc.name, func(b *testing.B) {
				pats := benchCompile(b, engine.useRe2, benchSSHPatterns...)
				dst := make(map[string]string)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					for _, p := range pats {
						if p.ParseInto(bc.line, dst) {
							break
						}
					}
				}
			})
		}
	}
}

// BenchmarkCompileBase guards the compile path: the whole pattern directory is compiled at
// startup, so anything added there shows up as engine startup time.
func BenchmarkCompileBase(b *testing.B) {
	for _, engine := range benchEngines {
		b.Run(engine.name, func(b *testing.B) {
			h := NewBase()
			h.UseRe2 = engine.useRe2

			names := make([]string, 0, len(h.Patterns))
			for name := range h.Patterns {
				names = append(names, name)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for _, name := range names {
					if _, err := h.Get(name); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
