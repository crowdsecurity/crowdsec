package challenge

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
)

func TestBoundFingerprintURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "short url is untouched",
			url:  "https://example.com/product?ref=abc#top",
			want: "https://example.com/product?ref=abc#top",
		},
		{
			name: "exactly at the limit is untouched",
			url:  "https://example.com/" + strings.Repeat("a", MaxFingerprintURLLen-20),
			want: "https://example.com/" + strings.Repeat("a", MaxFingerprintURLLen-20),
		},
		{
			name: "long query is dropped, path kept whole",
			url:  "https://example.com/search?q=" + strings.Repeat("x", 900),
			want: "https://example.com/search",
		},
		{
			name: "long fragment is dropped too",
			url:  "https://example.com/page#" + strings.Repeat("x", 900),
			want: "https://example.com/page",
		},
		{
			name: "long path is cut when dropping the query is not enough",
			url:  "https://example.com/" + strings.Repeat("p", 900) + "?q=1",
			want: ("https://example.com/" + strings.Repeat("p", 900))[:MaxFingerprintURLLen],
		},
		{
			name: "long path with no query is cut",
			url:  "https://example.com/" + strings.Repeat("p", 900),
			want: ("https://example.com/" + strings.Repeat("p", 900))[:MaxFingerprintURLLen],
		},
		{
			name: "unparseable value still gets bounded",
			url:  "ht!tp://[::bad::]/" + strings.Repeat("z", 900),
			want: ("ht!tp://[::bad::]/" + strings.Repeat("z", 900))[:MaxFingerprintURLLen],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := boundFingerprintURL(tc.url)
			require.Equal(t, tc.want, got)
			require.LessOrEqual(t, len(got), MaxFingerprintURLLen)
			require.True(t, utf8.ValidString(got), "result must stay valid UTF-8")
		})
	}
}

// A cut landing inside a multi-byte rune must back off, not emit a broken
// sequence: proto3 strings are required to be valid UTF-8.
func TestBoundFingerprintURLRuneBoundary(t *testing.T) {
	// "é" is two bytes, so a 256-byte cut lands mid-rune once the odd-length
	// prefix shifts the alignment.
	got := boundFingerprintURL("https://example.com/x/" + strings.Repeat("é", 400))

	require.True(t, utf8.ValidString(got))
	require.LessOrEqual(t, len(got), MaxFingerprintURLLen)
	assert.Greater(t, len(got), MaxFingerprintURLLen-4, "should back off by at most one rune")
}

// The bound applies on the way into the cookie only. on_challenge_submit rules
// read the decoded payload and must still see the full href.
func TestBoundFingerprintURLNotAppliedAtDecode(t *testing.T) {
	raw := `{"url": "https://example.com/?q=` + strings.Repeat("x", 900) + `"}`

	var fp FingerprintData
	require.NoError(t, fp.UnmarshalJSON([]byte(raw)))

	assert.Greater(t, len(fp.URL), MaxFingerprintURLLen)
}

// The regression this guards: an unbounded href pushed the sealed cookie past
// the size browsers guarantee, sealCookieV0 failed, and the visitor could never
// pass the challenge.
func TestSealWithOversizedURL(t *testing.T) {
	fp := FingerprintData{
		FSID: "FS1_00001000000000_00010h02ba",
		URL:  "https://example.com/landing?utm=" + strings.Repeat("x", 4000),
	}

	key := make([]byte, 32)
	notAfter := time.Now().Add(time.Hour).Unix()

	encoded, err := sealCookieV0(&pb.ChallengeCookie{
		Fingerprint:   fp.ToProto(),
		PowDifficulty: 20,
	}, key, notAfter, 0, "", []byte("ua"), MaxCookieLen)
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), MaxCookieLen)

	opened, err := openCookie(encoded, key, []byte("ua"), MaxCookieLen)
	require.NoError(t, err)

	got := fingerprintDataFromProto(opened.Envelope.GetFingerprint())
	assert.Equal(t, "https://example.com/landing", got.URL)
}
