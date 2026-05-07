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

// EpochSalt and the per-context info strings define the HKDF derivation used
// to produce per-epoch keys from the long-lived master secret. They are part
// of the wire protocol — changing them silently would invalidate every
// outstanding ticket and cookie across a fleet upgrade. Bump the version
// suffix when intentionally rotating.
const (
	keyringHKDFSalt        = "crowdsec-challenge-keyring-v1"
	keyringInfoSign        = "epoch-sign"        // for HMAC ticket / PoW MAC keys
	keyringInfoCookie      = "epoch-cookie"      // for AES-GCM cookie sealing
	keyringDerivedKeyBytes = 32                  // 256-bit keys throughout
	keyringClockSkew       = 1                   // accept currentEpoch + 1
	keyringDefaultMaxLive  = 3                   // currentEpoch and 2 prior
	keyringDefaultRotation = 5 * time.Minute     // rotation cadence
	keyringMinRotation     = 30 * time.Second    // floor for sanity
)

// epochKey bundles the two derived keys for a single epoch so a single map
// lookup answers both "sign this" and "seal this cookie".
type epochKey struct {
	sign   []byte // HMAC-SHA256 key for tickets / PoW MACs
	cookie []byte // raw key fed to crypto.go's HKDF for AES-256-GCM
}

// KeyRing produces per-epoch keys deterministically from a shared master
// secret. Two instances configured with the same masterSecret and rotation
// interval derive bit-identical keys for the same epoch — the property that
// lets distributed (multi-WAF) deployments sign and verify each other's
// challenges without coordination.
//
// Live window: KeyRing.Get returns a key for any epoch in
// [currentEpoch - maxLive + 1 ... currentEpoch + clockSkew]. Epochs outside
// that window are rejected to bound the verification cost an attacker can
// extract by submitting arbitrarily-stale or far-future epoch tags.
type KeyRing struct {
	masterSecret     []byte
	rotationInterval time.Duration
	maxLive          int
	clockSkew        int

	now func() time.Time // overridable for tests

	mu    sync.RWMutex
	cache map[int64]epochKey
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
		now:              time.Now,
		cache:            make(map[int64]epochKey),
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
	key := k.deriveOrCache(epoch)
	return epoch, key.sign
}

// CurrentCookie returns the epoch and cookie-sealing key for new cookies.
func (k *KeyRing) CurrentCookie() (int64, []byte) {
	epoch := k.CurrentEpoch()
	key := k.deriveOrCache(epoch)
	return epoch, key.cookie
}

// SignKey returns the HMAC key for an epoch if it's within the live window;
// returns (nil, false) otherwise.
func (k *KeyRing) SignKey(epoch int64) ([]byte, bool) {
	if !k.isLive(epoch) {
		return nil, false
	}
	return k.deriveOrCache(epoch).sign, true
}

// CookieKey returns the AES-key-input for an epoch if it's within the live
// window; returns (nil, false) otherwise.
func (k *KeyRing) CookieKey(epoch int64) ([]byte, bool) {
	if !k.isLive(epoch) {
		return nil, false
	}
	return k.deriveOrCache(epoch).cookie, true
}

// LiveEpochs returns every epoch currently in the live window, oldest first.
// Useful for try-decrypt fallbacks when a cookie predates the format that
// carries an explicit epoch.
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

// deriveOrCache returns the cached epochKey or derives and stores it.
// Pure function of (masterSecret, epoch) so two instances always agree.
func (k *KeyRing) deriveOrCache(epoch int64) epochKey {
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
	derived := epochKey{
		sign:   deriveEpochKey(k.masterSecret, epoch, keyringInfoSign),
		cookie: deriveEpochKey(k.masterSecret, epoch, keyringInfoCookie),
	}
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
		"epoch":           epoch,
		"current_epoch":   k.CurrentEpoch(),
		"derivation_us":   derivationDuration.Microseconds(),
		"cache_evicted":   evicted,
		"cache_size":      len(k.cache),
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

	r := hkdf.New(sha256.New, masterSecret, []byte(keyringHKDFSalt), info)

	out := make([]byte, keyringDerivedKeyBytes)
	if _, err := r.Read(out); err != nil {
		// HKDF cannot fail at this length with SHA-256; treat as unrecoverable.
		panic(fmt.Sprintf("keyring: hkdf read failed: %v", err))
	}
	return out
}
