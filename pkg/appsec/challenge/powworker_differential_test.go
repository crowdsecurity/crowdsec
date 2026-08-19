// Differential test for the browser PoW solver. pow-worker.js carries a
// hand-optimized single-block SHA-256 that must agree with crypto/sha256 down
// to the bit: if it drifts, clients mine nonces the server rejects and every
// challenge fails. Node isn't a build dependency, so these skip when it's
// missing.

package challenge

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// powShimJS drives the real, unmodified pow-worker.js by faking the bits of the
// worker global it touches. The solve is synchronous, so postMessage always
// fires before onmessage returns.
const powShimJS = `
const fs = require("fs"), vm = require("vm");
let result = null;
globalThis.self = { postMessage: (m) => { result = m; } };
vm.runInThisContext(fs.readFileSync(process.argv[2], "utf8"), { filename: "pow-worker.js" });
const [, , , salt, d, start, stride] = process.argv;
self.onmessage({ data: { p: salt, d: +d, start: +start, stride: +stride } });
process.stdout.write(String(result));
`

// runPowWorkerJS runs pow-worker.js under node, returning its output and
// whether it exited cleanly. The worker throws on a salt it can't use, which
// surfaces here as a non-nil error.
func runPowWorkerJS(t *testing.T, salt string, difficulty, start, stride int) (string, error) {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH; skipping JS/Go differential PoW test")
	}

	shim := filepath.Join(t.TempDir(), "shim.js")
	require.NoError(t, os.WriteFile(shim, []byte(powShimJS), 0o600))

	worker, err := filepath.Abs("pow-worker.js")
	require.NoError(t, err)

	out, err := exec.Command(node, shim, worker, salt,
		strconv.Itoa(difficulty), strconv.Itoa(start), strconv.Itoa(stride)).Output()

	return string(out), err
}

// powWorkerJS runs pow-worker.js under node and returns the nonce it finds.
func powWorkerJS(t *testing.T, salt string, difficulty, start, stride int) string {
	t.Helper()

	out, err := runPowWorkerJS(t, salt, difficulty, start, stride)
	require.NoError(t, err, "running pow-worker.js under node")

	return out
}

// TestPowWorkerJS_MatchesGo pins the JS solver to the Go one nonce-for-nonce.
// Both walk the nonce space in the same order, so an identical result means
// every rejected candidate along the way was rejected identically too — one
// run at d=16 is ~65k implicit hash comparisons per salt.
func TestPowWorkerJS_MatchesGo(t *testing.T) {
	for range 20 {
		salt := mustGeneratePowPrefix(t)
		require.Equal(t, solvePoWGo(salt, 16), powWorkerJS(t, salt, 16, 0, 1),
			"JS and Go disagree for salt %s", salt)
	}
}

// TestPowWorkerJS_SaltLengths pins the widest salts the solver accepts. 44 is
// the last length that still leaves room for an 11-char nonce inside one
// SHA-256 block; the odd lengths also exercise the word-alignment branch that
// decides how much of the message schedule can be treated as invariant.
func TestPowWorkerJS_SaltLengths(t *testing.T) {
	for _, tc := range []struct {
		name string
		salt string
	}{
		{"max length, word aligned", strings.Repeat("a", 44)},
		{"unaligned", strings.Repeat("a", 43)},
		{"unaligned, other residue", strings.Repeat("a", 42)},
		{"single char", "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, solvePoWGo(tc.salt, 12), powWorkerJS(t, tc.salt, 12, 0, 1))
		})
	}
}

// TestPowWorkerJS_RejectsUnusableSalt checks the solver fails loudly rather than
// quietly mining against a salt it can't hash in one block. There is no slow
// path to fall back to, so a wrong answer here would be far worse than an
// error: the client would burn CPU on nonces the server rejects.
func TestPowWorkerJS_RejectsUnusableSalt(t *testing.T) {
	for _, tc := range []struct {
		name string
		salt string
	}{
		{"one over the limit", strings.Repeat("a", powSaltMaxHexLen+1)},
		{"spans two blocks", strings.Repeat("a", 56)},
		{"non-ASCII", "héllo-salt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runPowWorkerJS(t, tc.salt, 12, 0, 1)
			require.Error(t, err, "solver should refuse salt %q, not solve it", tc.salt)
		})
	}
}

// TestPowWorkerJS_StridePartitions checks that splitting the nonce space across
// workers doesn't skip anything: the lanes together must find the same first
// solution a single worker would.
func TestPowWorkerJS_StridePartitions(t *testing.T) {
	const stride = 4

	for range 5 {
		salt := mustGeneratePowPrefix(t)

		best := -1

		for lane := range stride {
			nonce, err := strconv.ParseInt(powWorkerJS(t, salt, 16, lane, stride), 36, 64)
			require.NoError(t, err)
			require.Equal(t, lane, int(nonce)%stride, "lane %d strayed out of its slice", lane)

			if best < 0 || int(nonce) < best {
				best = int(nonce)
			}
		}

		require.Equal(t, solvePoWGo(salt, 16), formatBase36(best),
			"lanes missed the first solution for salt %s", salt)
	}
}

// TestPowWorkerJS_UnsolvableDifficulty guards the short-circuit that keeps
// "impossible" from pinning every core in the pool forever.
func TestPowWorkerJS_UnsolvableDifficulty(t *testing.T) {
	salt := mustGeneratePowPrefix(t)

	require.Equal(t, "0", powWorkerJS(t, salt, PowDifficultyDisabled, 0, 1))
	require.Equal(t, "0", powWorkerJS(t, salt, PowDifficultyImpossible, 0, 1))
}

// TestPowWorkerJS_Parses is cheap insurance: pow-worker.js is hand-edited and
// served raw, so nothing else would catch a syntax error before a browser did.
func TestPowWorkerJS_Parses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH")
	}

	out, err := exec.Command(node, "--check", "pow-worker.js").CombinedOutput()
	require.NoError(t, err, "pow-worker.js is not valid JS: %s", out)
}
