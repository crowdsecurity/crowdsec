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
	// MasterSecret is the long-lived secret used to sign tickets / PoW MACs
	// and seal challenge cookies. In a distributed deployment
	// all instances MUST share the same value. If unset,
	// the runtime generates an ephemeral random secret at startup
	MasterSecret *string `yaml:"master_secret"`

	// KeyRotationInterval controls how often the per-epoch challenge key
	// advances.
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

	// LibraryRuntimeObfuscationEnabled enables the background re-obfuscation
	// of the static library bundle at runtime. A version is shipped within build artifacts.
	LibraryRuntimeObfuscationEnabled *bool `yaml:"library_runtime_obfuscation_enabled"`

	// LibraryObfuscationPoolSize is the max number of obfuscated variants
	// of the library bundle to keep, defaults to 1.
	LibraryObfuscationPoolSize *int `yaml:"library_obfuscation_pool_size"`

	// LibraryObfuscationRefreshInterval is the cadence at which a single
	// new library-bundle variant is obfuscated, disabled by default.
	LibraryObfuscationRefreshInterval *time.Duration `yaml:"library_obfuscation_refresh_interval"`

	// LogLevel sets the challenge runtime's own log verbosity, independent of
	// the global level.
	LogLevel *log.Level `yaml:"log_level,omitempty"`
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
	if other.LibraryRuntimeObfuscationEnabled != nil {
		c.LibraryRuntimeObfuscationEnabled = other.LibraryRuntimeObfuscationEnabled
	}
	if other.LibraryObfuscationPoolSize != nil {
		c.LibraryObfuscationPoolSize = other.LibraryObfuscationPoolSize
	}
	if other.LibraryObfuscationRefreshInterval != nil {
		c.LibraryObfuscationRefreshInterval = other.LibraryObfuscationRefreshInterval
	}
	if other.LogLevel != nil {
		c.LogLevel = other.LogLevel
	}
}

// BuildOptions translates a (possibly nil) merged Config into the WithXxx
// Option list consumed by NewChallengeRuntime. Each unset field is simply not
// emitted so the runtime falls back to its built-in default. Returns the
// secret-validation error from ParseConfiguredSecret if MasterSecret is set
// but invalid.
//
// parent is the appsec logger the challenge runtime derives its own "challenge"
// sublogger from; the sublogger's level is the configured log_level, or the
// parent's level when unset. parent may be nil (falls back to the standard
// logger), e.g. in tests.
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

	return opts, nil
}
