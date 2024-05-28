package v1

import (
	"sync"
	"time"

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

func (rc *RevocationCache) Get(sn string, logger *log.Entry) (bool, bool) {
	rc.mu.RLock()
	entry, exists := rc.cache[sn]
	rc.mu.RUnlock()

	if !exists {
		logger.Tracef("TLSAuth: no cached value for cert %s", sn)
		return false, false
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if entry.timestamp.Add(rc.expiration).Before(time.Now()) {
		logger.Debugf("TLSAuth: cached value for %s expired, removing from cache", sn)
		delete(rc.cache, sn)

		return false, false
	}

	logger.Debugf("TLSAuth: using cached value for cert %s: %t", sn, entry.revoked)

	return entry.revoked, true
}

func (rc *RevocationCache) Set(sn string, revoked bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cache[sn] = cacheEntry{
		revoked:   revoked,
		timestamp: time.Now(),
	}
}
