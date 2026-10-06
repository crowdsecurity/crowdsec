package grok

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wasilibs/go-re2"
)

// fullParse is what ParseInto returned before captures were reduced: the regexp with every
// group capturing, read through the original semantics.
func fullParse(t *testing.T, h Host, expr, input string) map[string]string {
	t.Helper()

	var (
		ss []string
		s  map[string]int
	)
	if h.UseRe2 {
		r, sem, err := expand(h, expr, re2.Compile)
		require.NoError(t, err)
		ss, s = r.FindStringSubmatch(input), sem
	} else {
		r, sem, err := expand(h, expr, regexp.Compile)
		require.NoError(t, err)
		ss, s = r.FindStringSubmatch(input), sem
	}
	out := make(map[string]string)
	if len(ss) <= 1 || len(s) == 0 {
		return out
	}
	for sem, i := range s {
		out[sem] = ss[i]
	}
	return out
}

func numSubexp(p Pattern) int {
	return p.(interface{ NumSubexp() int }).NumSubexp()
}

func TestReducedCaptures(t *testing.T) {
	tests := []struct {
		name  string
		add   map[string]string
		expr  string
		input string
		want  map[string]string
		// capture groups left in the compiled regexp, 0 when it is kept as is
		groups int
	}{
		{
			name:   "unused groups are dropped",
			expr:   `(a|b)-%{PAIR:pair}-%{WORD}`,
			input:  "a-1-2-foo",
			want:   map[string]string{"pair": "1-2", "one": "1", "two": "2"},
			groups: 3,
		},
		{
			// escaped parentheses, and parentheses in a class
			name:   "parentheses that are not groups",
			add:    map[string]string{"ODD": `\((a)\) [(?P<]+`},
			expr:   `%{WORD:w} %{ODD} %{DIGIT:d}`,
			input:  "foo (a) (?P< 7",
			want:   map[string]string{"w": "foo", "d": "7"},
			groups: 2,
		},
		{
			name:   "named group without semantic is dropped",
			expr:   `(?P<user>\w+)-%{DIGIT:d}`,
			input:  "bob-7",
			want:   map[string]string{"d": "7"},
			groups: 1,
		},
		{
			name:   "unmatched alternation branch",
			expr:   `(?:%{DIGIT:d}|%{WORD:w})(x)`,
			input:  "abcx",
			want:   map[string]string{"d": "", "w": "abc"},
			groups: 2,
		},
		{
			name:   "flags and optional group",
			expr:   `(?i)x(%{DIGIT:d})?(y)`,
			input:  "XY",
			want:   map[string]string{"d": ""},
			groups: 1,
		},
		{
			name:  "every group is used",
			expr:  `%{DIGIT:a}-%{DIGIT:b}`,
			input: "1-2",
			want:  map[string]string{"a": "1", "b": "2"},
		},
		{
			// once the group is gone, the printer must keep the quantifier on the whole
			// content: ab+ or a** would match something else
			name:   "quantified groups",
			expr:   `(ab)+(a*)*(x|y)?-%{DIGIT:d}`,
			input:  "ababaay-7",
			want:   map[string]string{"d": "7"},
			groups: 1,
		},
		{
			name:   "alternation inside a concatenation",
			expr:   `x(a|bc)y%{DIGIT:d}()`,
			input:  "xbcy7",
			want:   map[string]string{"d": "7"},
			groups: 1,
		},
	}

	for _, engine := range []struct {
		name   string
		useRe2 bool
	}{{"legacy", false}, {"re2", true}} {
		for _, tc := range tests {
			t.Run(engine.name+"/"+tc.name, func(t *testing.T) {
				h := testHost(t, engine.useRe2)
				for name, expr := range tc.add {
					require.NoError(t, h.Add(name, expr))
				}

				p, err := h.Compile(tc.expr)
				require.NoError(t, err)

				require.Equal(t, tc.want, fullParse(t, h, tc.expr, tc.input))
				require.Equal(t, tc.want, parseMap(p, tc.input))

				if tc.groups == 0 {
					r, _, err := expand(h, tc.expr, regexp.Compile)
					require.NoError(t, err)
					require.Equal(t, r.NumSubexp(), numSubexp(p))
				} else {
					require.Equal(t, tc.groups, numSubexp(p))
				}
			})
		}
	}
}

// Every pattern of the base set and of the repository must parse exactly as it did with all
// groups capturing.
func TestReducedCapturesAllPatterns(t *testing.T) {
	inputs := []string{
		`127.0.0.1 - - [28/Jan/2016:14:19:36 +0300] "GET /zero.html HTTP/1.1" 200 398 "-" "Mozilla/5.0 (X11; Linux x86_64)"`,
		`192.168.1.1 - frank [20/Dec/2023:10:12:33 +0100] "POST /login?next=%2F HTTP/2.0" 302 0 "https://example.com/" "curl/8.0"`,
		`2016/01/28 14:19:36 [error] 1234#0: *5 open() "/var/www/x" failed (2: No such file or directory), client: 10.0.0.1, server: example.com`,
		"Jan 28 14:19:36 myhost sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2",
		"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8",
		"Jan 28 14:19:36 fw kernel: IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:00:1a:2b:3c:4d:5f:08:00 SRC=10.0.0.1 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=1234 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0",
		"2023-12-20 10:12:33.123 UTC [1234] postgres@db FATAL:  password authentication failed for user \"postgres\"",
		"https://user:pass@example.com:8443/path/to/file.php?a=1&b=2#frag",
		"fe80::1ff:fe23:4567:890a 2001:db8::1 00:1a:2b:3c:4d:5e 0123.4567.89ab",
		"2023-12-20T10:12:33+01:00 WARN something went wrong",
		"",
	}

	for _, engine := range []struct {
		name   string
		useRe2 bool
	}{{"legacy", false}, {"re2", true}} {
		t.Run(engine.name, func(t *testing.T) {
			h := NewBase()
			h.UseRe2 = engine.useRe2

			files, err := os.ReadDir(repository)
			require.NoError(t, err)
			for _, f := range files {
				require.NoError(t, h.AddFromFile(repoPath(f.Name())))
			}

			matches, reduced := 0, 0
			for name, expr := range h.Patterns {
				p, err := h.Get(name)
				require.NoError(t, err, name)

				full, _, err := expand(h, expr, regexp.Compile)
				require.NoError(t, err, name)
				if numSubexp(p) < full.NumSubexp() {
					reduced++
				}

				for _, in := range inputs {
					got := parseMap(p, in)
					require.Equal(t, fullParse(t, h, expr, in), got, "%s on %q", name, in)
					if len(got) > 0 {
						matches++
					}
				}
			}

			// a comparison of empty maps would prove nothing
			require.Greater(t, matches, 100)
			require.Greater(t, reduced, 100)
		})
	}
}
