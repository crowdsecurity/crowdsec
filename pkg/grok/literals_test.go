package grok

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractRequiredLiterals(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{
			name:    "plain literal",
			pattern: `Failed password for root`,
			want:    []string{"Failed password for root"},
		},
		{
			// only one branch has to match, so neither foo nor bar is required
			name:    "alternation contributes nothing",
			pattern: `(foo|bar)baz`,
			want:    []string{"baz"},
		},
		{
			name:    "optional group contributes nothing",
			pattern: `prefix(maybe)?suffix`,
			want:    []string{"prefix", "suffix"},
		},
		{
			name:    "star contributes nothing",
			pattern: `prefix.*suffix`,
			want:    []string{"prefix", "suffix"},
		},
		{
			// strings.Contains cannot look for a case-insensitive literal
			name:    "case-insensitive is skipped",
			pattern: `(?i)Failed password`,
			want:    nil,
		},
		{
			name:    "literal below the minimum length is dropped",
			pattern: `ab`,
			want:    nil,
		},
		{
			name:    "literal at the minimum length is kept",
			pattern: `a-b`,
			want:    []string{"a-b"},
		},
		{
			name:    "plus requires one occurrence",
			pattern: `(abc)+def`,
			want:    []string{"abc", "def"},
		},
		{
			name:    "repeat that may be absent contributes nothing",
			pattern: `(abc){0,2}defgh`,
			want:    []string{"defgh"},
		},
		{
			name:    "repeat of at least one is required",
			pattern: `(abc){2,3}defgh`,
			want:    []string{"defgh", "abc"},
		},
		{
			// longest first, capped, so a match never pays for more than maxLiterals scans
			name:    "longest first and capped",
			pattern: `alpha+beta+gamma+delta+epsilon`,
			want:    []string{"epsilon", "alph", "gamm"},
		},
		{
			name:    "escaped metacharacters are literals",
			pattern: `\[preauth\]`,
			want:    []string{"[preauth]"},
		},
		{
			// no filter rather than a wrong one
			name:    "unparseable pattern yields nothing",
			pattern: `%{DIGIT:d}(`,
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, extractRequiredLiterals(tc.pattern))
		})
	}
}

// Extraction runs on the expanded pattern, so check what a real parser node ends up with.
func TestExtractRequiredLiteralsOnGrok(t *testing.T) {
	tests := []struct {
		expr string
		want []string
	}{
		{
			expr: `Failed %{WORD:method} for %{USERNAME:user} from %{IP:src_ip} port %{NUMBER:port} %{WORD:proto}`,
			want: []string{"Failed ", " from ", " port "},
		},
		{
			expr: `Disconnected from authenticating user %{USERNAME:user} %{IP:src_ip} port %{NUMBER:port} \[preauth\]`,
			want: []string{"Disconnected from authenticating user ", " [preauth]", " port "},
		},
		{
			// everything else in this one is a single character, below the minimum length
			expr: `refused connect from %{DATA:host}\(%{IP:src_ip}\)`,
			want: []string{"refused connect from "},
		},
	}

	for _, engine := range []struct {
		name   string
		useRe2 bool
	}{{"legacy", false}, {"re2", true}} {
		for _, tc := range tests {
			t.Run(engine.name+"/"+tc.expr[:20], func(t *testing.T) {
				h := NewBase()
				h.UseRe2 = engine.useRe2

				p, err := h.Compile(tc.expr)
				require.NoError(t, err)
				require.Equal(t, tc.want, requiredLiteralsOf(p))
			})
		}
	}
}

func TestNoLiteralPrefilter(t *testing.T) {
	for _, engine := range []struct {
		name   string
		useRe2 bool
	}{{"legacy", false}, {"re2", true}} {
		t.Run(engine.name, func(t *testing.T) {
			h := NewBase()
			h.UseRe2 = engine.useRe2
			h.NoLiteralPrefilter = true

			p, err := h.Compile(`Failed %{WORD:method} for %{USERNAME:user}`)
			require.NoError(t, err)
			require.Empty(t, requiredLiteralsOf(p))

			dest := map[string]string{}
			require.True(t, p.ParseInto("Failed password for root", dest))
			require.Equal(t, "password", dest["method"])
		})
	}
}

// requiredLiteralsOf reaches into whichever implementation the host produced.
func requiredLiteralsOf(p Pattern) []string {
	if legacy, ok := p.(*PatternLegacy); ok {
		return legacy.requiredLiterals
	}
	return p.(*PatternRe2).requiredLiterals
}

// The one invariant that matters: a line the pattern matches must never be rejected by the
// pre-check. The reverse is only a missed optimization; this direction silently kills a parser.
// Seeded with every base pattern against a corpus of lines, so the seeds alone run in CI.
func FuzzLiteralPrefilterNeverRejectsAMatch(f *testing.F) {
	lines := []string{
		"Failed password for root from 192.168.1.1 port 22 ssh2",
		"Invalid user admin from 10.0.0.1 port 51234",
		`127.0.0.1 - - [28/Jan/2016:14:19:36 +0300] "GET /zero.html HTTP/1.1" 200 398 "-" "curl/8.0"`,
		"Jan 28 14:19:36 myhost sshd[1234]: Connection closed by 10.0.0.1 [preauth]",
		"2023-12-20T10:12:33+01:00 WARN something went wrong",
		"user@example.com /var/log/auth.log 00:1a:2b:3c:4d:5e",
		"",
		"----",
	}

	h := NewBase()
	for name := range h.Patterns {
		p, err := h.Get(name)
		if err != nil {
			continue
		}
		for _, line := range lines {
			f.Add(p.String(), line)
		}
	}

	f.Fuzz(func(t *testing.T, pattern, input string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Skip()
		}

		if !re.MatchString(input) {
			return
		}

		literals := extractRequiredLiterals(pattern)
		require.True(t, canMatch(literals, input),
			"pattern %q matches %q but the pre-check rejected it on literals %q", pattern, input, literals)
	})
}
