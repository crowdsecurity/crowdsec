package v1

import (
	"crypto/x509"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type cacheEntry struct {
	err       error // if nil, the certificate is not revocated
	timestamp time.Time
}

type RevocationCache struct {
	mu         sync.RWMutex
	cache      map[string]cacheEntry
	expiration time.Duration
	lastPurge  time.Time
	logger     *log.Entry
}

func NewRevocationCache(expiration time.Duration, logger *log.Entry) *RevocationCache {
	return &RevocationCache{
		cache:      make(map[string]cacheEntry),
		expiration: expiration,
		lastPurge:  time.Now(),
		logger:     logger,
	}
}

func (*RevocationCache) generateKey(cert *x509.Certificate) string {
	return cert.SerialNumber.String() + "-" + cert.Issuer.String()
}

// purge removes expired entries from the cache
func (rc *RevocationCache) purgeExpired() {
	// we don't keep a separate interval for the full sweep, we'll just double the expiration
	if time.Since(rc.lastPurge) < rc.expiration {
		return
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	for key, entry := range rc.cache {
		if time.Since(entry.timestamp) > rc.expiration {
			rc.logger.Debugf("purging expired entry for cert %s", key)
			delete(rc.cache, key)
		}
	}
}

func (rc *RevocationCache) Get(cert *x509.Certificate) (error, bool) { //nolint:revive
	rc.purgeExpired()
	key := rc.generateKey(cert)
	rc.mu.RLock()
	entry, exists := rc.cache[key]
	rc.mu.RUnlock()

	if !exists {
		rc.logger.Tracef("no cached value for cert %s", key)
		return nil, false
	}

	// Upgrade to write lock to potentially modify the cache
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if entry.timestamp.Add(rc.expiration).Before(time.Now()) {
		rc.logger.Debugf("cached value for %s expired, removing from cache", key)
		delete(rc.cache, key)

		return nil, false
	}

	rc.logger.Debugf("using cached value for cert %s: %v", key, entry.err)

	return entry.err, true
}

func (rc *RevocationCache) Set(cert *x509.Certificate, err error) {
	key := rc.generateKey(cert)

	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cache[key] = cacheEntry{
		err:       err,
		timestamp: time.Now(),
	}
}

func (rc *RevocationCache) Empty() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.cache = make(map[string]cacheEntry)
}
