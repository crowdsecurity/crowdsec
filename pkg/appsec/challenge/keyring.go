package challenge

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

// keyringHKDFSalt and the per-context info strings define the HKDF
// derivations used to turn the long-lived master secret into operational
// keys. They are part of the wire protocol — changing them silently would
// invalidate every outstanding ticket and cookie across a fleet upgrade.
// Bump the version suffix when intentionally rotating.
//
// Two independent derivation contexts are used:
//
//   - "epoch-sign":   per-epoch HMAC key for ticket / PoW MAC signing.
//     Rotates with the keyring (tight forgery window).
//   - "cookie-master": single long-lived AES key for cookie sealing.
//     Lifetime equals master_secret's lifetime; cookie
//     expiration is enforced by an explicit not_after
//     timestamp inside the sealed envelope (see crypto.go).
//
// The two contexts produce cryptographically independent keys: leaking
// one tells the attacker nothing about the other.
const (
	keyringHKDFSalt         = "crowdsec-challenge-keyring-v1"
	keyringInfoSign         = "epoch-sign"
	keyringInfoMasterCookie = "cookie-master"
	keyringDerivedKeyBytes  = 32 // 256-bit keys throughout
	keyringClockSkew        = 1  // accept currentEpoch + 1
	keyringDefaultMaxLive   = 3  // currentEpoch and 2 prior
	keyringDefaultRotation  = 5 * time.Minute
	keyringMinRotation      = 30 * time.Second
)

// KeyRing produces keys deterministically from a shared master secret. Two
// instances configured with the same masterSecret derive bit-identical
// keys — the property that lets distributed (multi-WAF) deployments sign
// and verify each other's challenges and cookies without coordination.
//
// Two key families with different lifetimes:
//
//   - Per-epoch signing key (rotates on rotationInterval). Used for ticket
//     HMAC and PoW MAC. Live window:
//     [currentEpoch - maxLive + 1 ... currentEpoch + clockSkew]
//     Epochs outside the window are rejected, bounding ticket forgery
//     exposure to maxLive * rotationInterval.
//
//   - Long-lived master cookie key (no rotation). Used for AES-GCM cookie
//     sealing. Cookie expiration is enforced by an explicit not_after
//     timestamp inside the sealed envelope, NOT by key eviction — so
//     cookie TTL can be much larger than the ticket window without
//     widening ticket forgery exposure.
type KeyRing struct {
	masterSecret     []byte
	rotationInterval time.Duration
	maxLive          int
	clockSkew        int

	// masterCookieKey is the long-lived cookie-sealing key; derived once
	// at construction. Pointer-receiver methods read it without locking
	// because it's never mutated after NewKeyRing returns.
	masterCookieKey []byte

	now func() time.Time // overridable for tests

	mu    sync.RWMutex
	cache map[int64][]byte // epoch -> per-epoch sign key
}

// NewKeyRing constructs a KeyRing. masterSecret must be at least minSecretBytes
// long (callers should already have validated this via WithMasterSecret); the
// rotation interval must be at least keyringMinRotation. maxLive defaults to
// keyringDefaultMaxLive when zero.
func NewKeyRing(masterSecret []byte, rotationInterval time.Duration, maxLive int) (*KeyRing, error) {
	if len(masterSecret) < minSecretBytes {
		return nil, fmt.Errorf("keyring master secret is %d bytes; minimum is %d", len(masterSecret), minSecretBytes)
	}
	if rotationInterval < keyringMinRotation {
		return nil, fmt.Errorf("keyring rotation interval %s is below the floor %s", rotationInterval, keyringMinRotation)
	}
	if maxLive <= 0 {
		maxLive = keyringDefaultMaxLive
	}

	return &KeyRing{
		masterSecret:     masterSecret,
		rotationInterval: rotationInterval,
		maxLive:          maxLive,
		clockSkew:        keyringClockSkew,
		masterCookieKey:  deriveMasterCookieKey(masterSecret),
		now:              time.Now,
		cache:            make(map[int64][]byte),
	}, nil
}

// CurrentEpoch returns the epoch identifier for the current wall-clock time.
// Equal across all instances with synchronized clocks.
func (k *KeyRing) CurrentEpoch() int64 {
	return k.now().Unix() / int64(k.rotationInterval/time.Second)
}

// Current returns the epoch and signing key that should be used to sign new
// outbound material right now.
func (k *KeyRing) Current() (int64, []byte) {
	epoch := k.CurrentEpoch()
	return epoch, k.deriveOrCache(epoch)
}

// SignKey returns the HMAC key for an epoch if it's within the live window;
// returns (nil, false) otherwise.
func (k *KeyRing) SignKey(epoch int64) ([]byte, bool) {
	if !k.isLive(epoch) {
		return nil, false
	}
	return k.deriveOrCache(epoch), true
}

// MasterCookieKey returns the long-lived AES-key-input for cookie sealing.
// Does not depend on epoch; same value for the lifetime of the master
// secret. Cookie expiration is enforced via an explicit not_after timestamp
// inside the sealed envelope (see crypto.go).
func (k *KeyRing) MasterCookieKey() []byte {
	return k.masterCookieKey
}

// LiveEpochs returns every epoch currently in the live window, oldest first.
// Used by callers that need to enumerate the acceptable ticket-signing epochs.
func (k *KeyRing) LiveEpochs() []int64 {
	current := k.CurrentEpoch()
	out := make([]int64, 0, k.maxLive+k.clockSkew)
	for e := current - int64(k.maxLive-1); e <= current+int64(k.clockSkew); e++ {
		out = append(out, e)
	}
	return out
}

func (k *KeyRing) isLive(epoch int64) bool {
	current := k.CurrentEpoch()
	return epoch >= current-int64(k.maxLive-1) && epoch <= current+int64(k.clockSkew)
}

// deriveOrCache returns the cached per-epoch signing key or derives and
// stores it. Pure function of (masterSecret, epoch) so two instances
// always agree.
func (k *KeyRing) deriveOrCache(epoch int64) []byte {
	k.mu.RLock()
	if cached, ok := k.cache[epoch]; ok {
		k.mu.RUnlock()
		return cached
	}
	k.mu.RUnlock()

	k.mu.Lock()
	defer k.mu.Unlock()

	// Re-check after acquiring the write lock.
	if cached, ok := k.cache[epoch]; ok {
		return cached
	}

	start := time.Now()
	derived := deriveEpochKey(k.masterSecret, epoch, keyringInfoSign)
	derivationDuration := time.Since(start)

	// Bound the cache so it can't grow without limit if the clock jumps.
	// Anything outside the live window is safe to evict.
	evicted := 0
	for cachedEpoch := range k.cache {
		if !k.isLive(cachedEpoch) {
			delete(k.cache, cachedEpoch)
			evicted++
		}
	}

	k.cache[epoch] = derived

	// One INFO line per fresh epoch derivation. HKDF itself is microseconds
	// — we log it for distributed-troubleshooting visibility (every WAF
	// instance with the same master_secret should log the same epoch
	// numbers at the same wall-clock times) and to surface unexpected
	// rotation churn (clock jumps, mis-sized live window, etc.).
	log.WithFields(log.Fields{
		"epoch":         epoch,
		"current_epoch": k.CurrentEpoch(),
		"derivation_us": derivationDuration.Microseconds(),
		"cache_evicted": evicted,
		"cache_size":    len(k.cache),
	}).Info("WAF challenge: derived per-epoch key")

	return derived
}

// deriveEpochKey performs HKDF-SHA256 with a stable salt and a context-
// specific info value: <context bytes> || ':' || <epoch_be8>. Two instances
// with the same masterSecret always derive the same bytes for the same epoch
// and context — this is what makes distributed agreement work.
//
// The colon separator prevents context-prefix collisions (e.g. avoids "epoch"
// + "sign" colliding with "epochs" + "ign").
func deriveEpochKey(masterSecret []byte, epoch int64, context string) []byte {
	info := make([]byte, 0, len(context)+1+8)
	info = append(info, context...)
	info = append(info, ':')
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], uint64(epoch))
	info = append(info, epochBytes[:]...)

	return hkdfExtract(masterSecret, info)
}

// deriveMasterCookieKey performs HKDF-SHA256 with no epoch component, so
// the output depends only on the master secret. Identical across all
// instances sharing the master, stable for the lifetime of the master.
// Cookie expiration is enforced separately by a not_after timestamp
// inside the sealed envelope (see crypto.go).
func deriveMasterCookieKey(masterSecret []byte) []byte {
	return hkdfExtract(masterSecret, []byte(keyringInfoMasterCookie))
}

// hkdfExtract is the shared HKDF-SHA256 call used by both derivation
// helpers. Salt is the fixed keyringHKDFSalt; info is caller-supplied
// (already disambiguated by context).
//
// The Read at a 32-byte fixed output with SHA-256 is documented as
// infallible: HKDF-Expand only fails when asked for more than
// 255 * HashLen bytes, and 32 is well under SHA-256's 8160-byte limit.
// A non-nil error here is therefore an invariant violation (e.g. the
// runtime/crypto stack itself is broken), not a recoverable runtime
// condition. Panic is appropriate: the alternative would be threading
// a (string, error) return through every derivation site to handle a
// case the standard library guarantees cannot occur.
func hkdfExtract(masterSecret []byte, info []byte) []byte {
	r := hkdf.New(sha256.New, masterSecret, []byte(keyringHKDFSalt), info)

	out := make([]byte, keyringDerivedKeyBytes)
	if _, err := r.Read(out); err != nil {
		panic(fmt.Sprintf("keyring: hkdf read failed (should be unreachable): %v", err))
	}
	return out
}
