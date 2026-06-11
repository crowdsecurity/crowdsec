// config.go defines the YAML-facing challenge configuration. Multiple
// appsec-config files can each contribute a disjoint subset; MergeFrom
// composes them without one wiping the others. Once merged, BuildOptions
// translates the Config into the runtime's functional-option list
// (NewChallengeRuntime(...)).

package challenge

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/logging"
)

// Config carries the YAML-configurable challenge runtime settings.
type Config struct {
	// MasterSecret is the long-lived secret all per-epoch HMAC keys and the
	// cookie-sealing AES key derive from. In a distributed deployment every
	// instance MUST share the same value to sign/verify each other's
	// challenges. If unset, the runtime generates an ephemeral random secret
	// at startup — fine for a single instance, but restarts then invalidate
	// outstanding cookies.
	MasterSecret *string `yaml:"master_secret"`

	// KeyRotationInterval is the per-epoch key advance period. All instances
	// in a distributed setup MUST agree on it to derive identical keys.
	// Defaults to 5m.
	KeyRotationInterval *time.Duration `yaml:"key_rotation_interval"`

	// MaxLiveEpochs is how many past epochs (besides the current one) the
	// keyring keeps accepting, so in-flight submissions aren't invalidated at
	// a rotation boundary. Bounds ticket-forgery exposure to
	// MaxLiveEpochs × KeyRotationInterval. Defaults to 3.
	MaxLiveEpochs *int `yaml:"max_live_epochs"`

	// CookieTTL is how long a successful-challenge cookie stays valid.
	// Decoupled from the keyring window (enforced by a not_after stamp inside
	// the sealed cookie, not key eviction) so cookies can be long-lived while
	// per-epoch keys rotate tightly. Defaults to 12h.
	CookieTTL *time.Duration `yaml:"cookie_ttl"`

	// MaxCookieSize caps the challenge cookie's encoded size, enforced on both
	// seal and open. It bounds the memory allocated from the (attacker-supplied)
	// fingerprint envelope, closing an over-allocation DoS. Defaults to
	// MaxCookieLen (4096, the per-cookie size browsers guarantee); raise it only
	// if a non-browser client tolerates larger cookies.
	MaxCookieSize *int `yaml:"max_cookie_size"`

	// CryptoObfuscationPoolSize is how many obfuscations of the per-epoch
	// sign-key module to keep per live epoch. Each variant embeds the same key
	// with different byte layout, giving per-visitor variance. Defaults to 1.
	CryptoObfuscationPoolSize *int `yaml:"crypto_obfuscation_pool_size"`

	// LibraryRuntimeObfuscationEnabled gates background re-obfuscation of the
	// public library bundle. The bundle is ALWAYS obfuscated at build time;
	// this only adds further runtime variants at ~1 minute of CPU per pass.
	// Off by default (serve only the baked-in variant).
	LibraryRuntimeObfuscationEnabled *bool `yaml:"library_runtime_obfuscation_enabled"`

	// LibraryObfuscationPoolSize is the max number of library-bundle variants
	// to keep. Only meaningful when LibraryRuntimeObfuscationEnabled is set.
	// Defaults to 1.
	LibraryObfuscationPoolSize *int `yaml:"library_obfuscation_pool_size"`

	// LibraryObfuscationRefreshInterval is the cadence at which one new
	// library-bundle variant is obfuscated (oldest evicted) — one per tick, so
	// a full rotation takes pool_size × interval. Ignored unless
	// LibraryRuntimeObfuscationEnabled is set.
	LibraryObfuscationRefreshInterval *time.Duration `yaml:"library_obfuscation_refresh_interval"`

	// SpentSetMaxEntries caps the replay-protection LRU. A deep DoS backstop;
	// steady-state stays far below it. Defaults to spentSetDefaultMaxEntries.
	SpentSetMaxEntries *int `yaml:"spent_set_max_entries"`

	// LogLevel sets the challenge runtime's own log verbosity, independent of
	// the global level. Note: `panic` is not supported — logrus.PanicLevel is 0,
	// which SubLogger (pkg/logging/sublogger.go) treats as "inherit the parent level".
	LogLevel *log.Level `yaml:"log_level,omitempty"`
}

// MergeFrom overlays the non-nil fields of other onto c, field by field, so
// multiple appsec-configs can each contribute a disjoint subset (last non-nil
// wins). A nil receiver or argument is a no-op.
func (c *Config) MergeFrom(other *Config) {
	if c == nil || other == nil {
		return
	}

	if other.MasterSecret != nil {
		c.MasterSecret = other.MasterSecret
	}
	if other.KeyRotationInterval != nil {
		c.KeyRotationInterval = other.KeyRotationInterval
	}
	if other.MaxLiveEpochs != nil {
		c.MaxLiveEpochs = other.MaxLiveEpochs
	}
	if other.CookieTTL != nil {
		c.CookieTTL = other.CookieTTL
	}
	if other.MaxCookieSize != nil {
		c.MaxCookieSize = other.MaxCookieSize
	}
	if other.CryptoObfuscationPoolSize != nil {
		c.CryptoObfuscationPoolSize = other.CryptoObfuscationPoolSize
	}
	if other.LibraryRuntimeObfuscationEnabled != nil {
		c.LibraryRuntimeObfuscationEnabled = other.LibraryRuntimeObfuscationEnabled
	}
	if other.LibraryObfuscationPoolSize != nil {
		c.LibraryObfuscationPoolSize = other.LibraryObfuscationPoolSize
	}
	if other.LibraryObfuscationRefreshInterval != nil {
		c.LibraryObfuscationRefreshInterval = other.LibraryObfuscationRefreshInterval
	}
	if other.SpentSetMaxEntries != nil {
		c.SpentSetMaxEntries = other.SpentSetMaxEntries
	}
	if other.LogLevel != nil {
		c.LogLevel = other.LogLevel
	}
}

// BuildOptions translates a (possibly nil) merged Config into the WithXxx
// Option list for NewChallengeRuntime; unset fields are omitted so the runtime
// uses its built-in defaults. Returns an error if MasterSecret is set but
// invalid. parent (may be nil) is the logger the "challenge" sublogger derives
// from, at the configured log_level or parent's level.
func BuildOptions(c *Config, parent *log.Entry) ([]Option, error) {
	// Always give the runtime its own component sublogger.
	base := log.StandardLogger()
	if parent != nil {
		base = parent.Logger
	}

	var lvl log.Level
	if c != nil && c.LogLevel != nil {
		lvl = *c.LogLevel
	}

	opts := []Option{WithLogger(logging.SubLogger(base, "challenge", lvl))}

	if c == nil {
		return opts, nil
	}

	if c.MasterSecret != nil && *c.MasterSecret != "" {
		secret, err := ParseConfiguredSecret(*c.MasterSecret)
		if err != nil {
			return nil, fmt.Errorf("invalid challenge master_secret: %w", err)
		}
		opts = append(opts, WithMasterSecret(secret))
	}
	if c.KeyRotationInterval != nil {
		opts = append(opts, WithRotationInterval(*c.KeyRotationInterval))
	}
	if c.MaxLiveEpochs != nil && *c.MaxLiveEpochs > 0 {
		opts = append(opts, WithMaxLiveEpochs(*c.MaxLiveEpochs))
	}
	if c.CookieTTL != nil {
		opts = append(opts, WithCookieTTL(*c.CookieTTL))
	}
	if c.MaxCookieSize != nil && *c.MaxCookieSize > 0 {
		opts = append(opts, WithMaxCookieLen(*c.MaxCookieSize))
	}
	if c.CryptoObfuscationPoolSize != nil && *c.CryptoObfuscationPoolSize > 0 {
		opts = append(opts, WithCryptoObfuscationPoolSize(*c.CryptoObfuscationPoolSize))
	}
	if c.LibraryRuntimeObfuscationEnabled != nil {
		opts = append(opts, WithLibraryRuntimeObfuscationEnabled(*c.LibraryRuntimeObfuscationEnabled))
	}
	if c.LibraryObfuscationPoolSize != nil && *c.LibraryObfuscationPoolSize > 0 {
		opts = append(opts, WithLibraryObfuscationPoolSize(*c.LibraryObfuscationPoolSize))
	}
	if c.LibraryObfuscationRefreshInterval != nil {
		opts = append(opts, WithLibraryObfuscationRefreshInterval(*c.LibraryObfuscationRefreshInterval))
	}
	if c.SpentSetMaxEntries != nil && *c.SpentSetMaxEntries > 0 {
		opts = append(opts, WithSpentSetMaxEntries(*c.SpentSetMaxEntries))
	}

	return opts, nil
}
