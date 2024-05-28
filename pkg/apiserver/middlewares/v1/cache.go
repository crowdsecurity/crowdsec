package v1

import (
	"sync"
	"time"

	"crypto/x509"

	log "github.com/sirupsen/logrus"
)

type cacheEntry struct {
	revoked   bool
	timestamp time.Time
}

type RevocationCache struct {
	mu         sync.RWMutex
	cache      map[string]cacheEntry
	expiration time.Duration
}

func NewRevocationCache(expiration time.Duration) *RevocationCache {
	return &RevocationCache{
		cache:      make(map[string]cacheEntry),
		expiration: expiration,
	}
}

func (*RevocationCache) generateKey(cert *x509.Certificate, issuer *x509.Certificate) string {
	return cert.SerialNumber.String() + "-" + issuer.Subject.String()
}

func (rc *RevocationCache) Get(cert *x509.Certificate, issuer *x509.Certificate, logger *log.Entry) (bool, bool) {
	key := rc.generateKey(cert, issuer)
	rc.mu.RLock()
	entry, exists := rc.cache[key]
	rc.mu.RUnlock()

	if !exists {
		logger.Tracef("TLSAuth: no cached value for cert %s", key)
		return false, false
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if entry.timestamp.Add(rc.expiration).Before(time.Now()) {
		logger.Debugf("TLSAuth: cached value for %s expired, removing from cache", key)
		delete(rc.cache, key)

		return false, false
	}

	logger.Debugf("TLSAuth: using cached value for cert %s: %t", key, entry.revoked)

	return entry.revoked, true
}

func (rc *RevocationCache) Set(cert *x509.Certificate, issuer *x509.Certificate, revoked bool) {
	key := rc.generateKey(cert, issuer)

	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cache[key] = cacheEntry{
		revoked:   revoked,
		timestamp: time.Now(),
	}
}
