package challenge

import (
	"fmt"
	"time"
)

// Config carries the YAML-configurable challenge runtime settings. All fields
// are pointers so the loader can distinguish "unset" from a zero value: this
// lets multiple appsec-configs each contribute a disjoint subset of fields
// without one wiping out the others on merge.
//
// Field semantics mirror the corresponding WithXxx options on the runtime; see
// their doc-comments for the operational meaning of each value.
type Config struct {
	// MasterSecret is the long-lived secret used to sign tickets / PoW MACs
	// and seal challenge cookies. In a distributed (multi-WAF) deployment
	// all instances MUST share the same value. May be a hex-encoded byte
	// string or a raw passphrase; minimum 32 bytes / characters. If unset,
	// the runtime generates an ephemeral random secret at startup (suitable
	// for single-instance deployments only — restarts invalidate
	// outstanding challenge cookies).
	MasterSecret *string `yaml:"master_secret"`

	// KeyRotationInterval controls how often the per-epoch challenge key
	// advances. All instances in a distributed setup MUST agree on this
	// value to derive identical per-epoch keys.
	KeyRotationInterval *time.Duration `yaml:"key_rotation_interval"`

	// MaxLiveEpochs is how many past epochs (in addition to the current
	// one) the keyring continues to accept.
	MaxLiveEpochs *int `yaml:"max_live_epochs"`

	// CookieTTL controls how long a successful-challenge cookie stays
	// valid. Decoupled from the keyring rotation window. Defaults to 12h.
	CookieTTL *time.Duration `yaml:"cookie_ttl"`

	// CryptoObfuscationPoolSize is the number of distinct obfuscations of
	// the per-epoch sign-key module to keep per live epoch. Default 1.
	CryptoObfuscationPoolSize *int `yaml:"crypto_obfuscation_pool_size"`

	// LibraryObfuscationEnabled gates the background re-obfuscation of the
	// static library bundle. Off by default — the runtime serves only the
	// baked-in obfuscated bundle.
	LibraryObfuscationEnabled *bool `yaml:"library_obfuscation_enabled"`

	// LibraryObfuscationPoolSize is the max number of runtime-obfuscated
	// variants of the library bundle to keep when library obfuscation is
	// enabled. Ignored when disabled. Default 3.
	LibraryObfuscationPoolSize *int `yaml:"library_obfuscation_pool_size"`

	// LibraryObfuscationRefreshInterval is the cadence at which a single
	// new library-bundle variant is obfuscated and added to the pool when
	// library obfuscation is enabled. Ignored when disabled. Default 1h.
	LibraryObfuscationRefreshInterval *time.Duration `yaml:"library_obfuscation_refresh_interval"`
}

// MergeFrom overlays the non-nil fields of other onto c, field by field.
// Used when multiple appsec-configs are loaded: each later config contributes
// (or overrides) a subset of fields while leaving the others intact. Mirrors
// the "last wins for overrides, append for collections" pattern that the rest
// of LoadByPath uses for scalar fields.
//
// Calling MergeFrom on a nil *Config is a no-op (returns silently); the caller
// is expected to have allocated the receiver before merging into it.
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
	if other.CryptoObfuscationPoolSize != nil {
		c.CryptoObfuscationPoolSize = other.CryptoObfuscationPoolSize
	}
	if other.LibraryObfuscationEnabled != nil {
		c.LibraryObfuscationEnabled = other.LibraryObfuscationEnabled
	}
	if other.LibraryObfuscationPoolSize != nil {
		c.LibraryObfuscationPoolSize = other.LibraryObfuscationPoolSize
	}
	if other.LibraryObfuscationRefreshInterval != nil {
		c.LibraryObfuscationRefreshInterval = other.LibraryObfuscationRefreshInterval
	}
}

// BuildOptions translates a (possibly nil) merged Config into the WithXxx
// Option list consumed by NewChallengeRuntime. Each unset field is simply not
// emitted so the runtime falls back to its built-in default. Returns the
// secret-validation error from ParseConfiguredSecret if MasterSecret is set
// but invalid.
func BuildOptions(c *Config) ([]Option, error) {
	if c == nil {
		return nil, nil
	}

	var opts []Option

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
	if c.CryptoObfuscationPoolSize != nil && *c.CryptoObfuscationPoolSize > 0 {
		opts = append(opts, WithCryptoObfuscationPoolSize(*c.CryptoObfuscationPoolSize))
	}
	if c.LibraryObfuscationEnabled != nil {
		opts = append(opts, WithLibraryObfuscationEnabled(*c.LibraryObfuscationEnabled))
	}
	if c.LibraryObfuscationPoolSize != nil && *c.LibraryObfuscationPoolSize > 0 {
		opts = append(opts, WithLibraryObfuscationPoolSize(*c.LibraryObfuscationPoolSize))
	}
	if c.LibraryObfuscationRefreshInterval != nil {
		opts = append(opts, WithLibraryObfuscationRefreshInterval(*c.LibraryObfuscationRefreshInterval))
	}

	return opts, nil
}
