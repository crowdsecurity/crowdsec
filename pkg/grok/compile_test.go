package grok

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func testHost(t *testing.T, useRe2 bool) Host {
	t.Helper()

	h := New()
	h.UseRe2 = useRe2
	require.NoError(t, h.Add("DIGIT", `\d`))
	require.NoError(t, h.Add("WORD", `\w+`))
	require.NoError(t, h.Add("PAIR", `%{DIGIT:one}-%{DIGIT:two}`))

	return h
}

func TestCompile(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		input   string
		want    map[string]string
		wantErr string
	}{
		{
			name:  "plain regexp",
			expr:  `(?P<x>\d+)`,
			input: "42",
			want:  map[string]string{},
		},
		{
			name:  "named subpatterns",
			expr:  `%{WORD:name}/%{DIGIT:age}`,
			input: "alice/7",
			want:  map[string]string{"name": "alice", "age": "7"},
		},
		{
			name:  "capturing group before subpattern shifts the index",
			expr:  `(a|b)-%{WORD:w}`,
			input: "b-foo",
			want:  map[string]string{"w": "foo"},
		},
		{
			name:  "non-capturing group before subpattern",
			expr:  `(?:a|b)-%{WORD:w}`,
			input: "b-foo",
			want:  map[string]string{"w": "foo"},
		},
		{
			name:  "nested semantics are propagated",
			expr:  `%{PAIR:pair}-%{DIGIT:three}`,
			input: "1-2-3",
			want:  map[string]string{"pair": "1-2", "one": "1", "two": "2", "three": "3"},
		},
		{
			name:  "outer semantic wins over inner one with the same name",
			expr:  `%{PAIR:one}`,
			input: "1-2",
			want:  map[string]string{"one": "1-2", "two": "2"},
		},
		{
			name:  "no match",
			expr:  `%{DIGIT:d}`,
			input: "x",
			want:  map[string]string{},
		},
		{
			name:    "unknown subpattern",
			expr:    `%{NOPE:x}`,
			wantErr: "the 'NOPE' pattern doesn't exist",
		},
		{
			name:    "invalid regexp",
			expr:    `%{DIGIT:d}(`,
			wantErr: "missing closing )",
		},
	}

	for _, engine := range []struct {
		name   string
		useRe2 bool
	}{{"legacy", false}, {"re2", true}} {
		for _, tc := range tests {
			t.Run(engine.name+"/"+tc.name, func(t *testing.T) {
				h := testHost(t, engine.useRe2)

				p, err := h.Compile(tc.expr)
				if tc.wantErr != "" {
					require.ErrorContains(t, err, tc.wantErr)
					return
				}

				require.NoError(t, err)
				require.Equal(t, tc.want, p.Parse(tc.input))
			})
		}
	}
}

// Both engines must expand every base pattern to the same regexp with the same semantics.
func TestCompileEnginesAgreeOnBase(t *testing.T) {
	legacy := NewBase()
	re2 := NewBase()
	re2.UseRe2 = true

	for name := range legacy.Patterns {
		lp, err := legacy.Get(name)
		require.NoError(t, err, name)
		rp, err := re2.Get(name)
		require.NoError(t, err, name)

		require.Equal(t, lp.String(), rp.String(), name)
		require.Equal(t, lp.(*PatternLegacy).s, rp.(*PatternRe2).s, name)
	}
}

func TestParseInto(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		input string
		dest  map[string]string
		want  bool
		after map[string]string
	}{
		{
			name:  "match writes captures",
			expr:  `%{PAIR:pair}`,
			input: "1-2",
			dest:  map[string]string{},
			want:  true,
			after: map[string]string{"pair": "1-2", "one": "1", "two": "2"},
		},
		{
			name:  "existing keys are kept",
			expr:  `%{DIGIT:d}`,
			input: "7",
			dest:  map[string]string{"program": "sshd", "d": "stale"},
			want:  true,
			after: map[string]string{"program": "sshd", "d": "7"},
		},
		{
			name:  "no match leaves dest untouched",
			expr:  `%{DIGIT:d}`,
			input: "nope",
			dest:  map[string]string{"program": "sshd"},
			want:  false,
			after: map[string]string{"program": "sshd"},
		},
		{
			// an unmatched optional group yields an empty capture, which still counts as a match
			name:  "empty capture still matches",
			expr:  `(?:%{DIGIT:one})-(?:%{DIGIT:two})?`,
			input: "1-",
			dest:  map[string]string{},
			want:  true,
			after: map[string]string{"one": "1", "two": ""},
		},
		{
			// node.go reads "no captures" as a node failure, so a pattern that cannot
			// produce any must report false even when the regexp itself matches
			name:  "capture group without semantic does not match",
			expr:  `(\d)-(\d)`,
			input: "1-2",
			dest:  map[string]string{},
			want:  false,
			after: map[string]string{},
		},
		{
			name:  "subpattern without semantic does not match",
			expr:  `%{DIGIT}-%{DIGIT}`,
			input: "1-2",
			dest:  map[string]string{},
			want:  false,
			after: map[string]string{},
		},
	}

	for _, engine := range []struct {
		name   string
		useRe2 bool
	}{{"legacy", false}, {"re2", true}} {
		for _, tc := range tests {
			t.Run(engine.name+"/"+tc.name, func(t *testing.T) {
				h := testHost(t, engine.useRe2)

				p, err := h.Compile(tc.expr)
				require.NoError(t, err)

				require.Equal(t, tc.want, p.ParseInto(tc.input, tc.dest))
				require.Equal(t, tc.after, tc.dest)
			})
		}
	}
}

// Parse is a thin wrapper over ParseInto and must keep returning an empty (not nil) map
// on failure: callers test the length of the result.
func TestParseMatchesParseInto(t *testing.T) {
	for _, engine := range []struct {
		name   string
		useRe2 bool
	}{{"legacy", false}, {"re2", true}} {
		t.Run(engine.name, func(t *testing.T) {
			h := testHost(t, engine.useRe2)

			p, err := h.Compile(`%{PAIR:pair}`)
			require.NoError(t, err)

			into := map[string]string{}
			require.True(t, p.ParseInto("1-2", into))
			require.Equal(t, into, p.Parse("1-2"))

			require.Equal(t, map[string]string{}, p.Parse("nope"))
		})
	}
}
