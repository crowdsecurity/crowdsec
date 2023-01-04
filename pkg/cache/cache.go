package cache

import (
	"time"

	"github.com/bluele/gcache"
	log "github.com/sirupsen/logrus"
)

var Caches []gcache.Cache
var CacheNames []string
var CacheConfig []CacheCfg

type CacheCfg struct {
	Name     string
	Size     int
	TTL      time.Duration
	Strategy int
}

func CacheInit(cfg CacheCfg) error {
	for _, name := range CacheNames {
		if name == cfg.Name {
			log.Infof("Cache %s already exists", cfg.Name)
		}
	}
	CTICache := gcache.New(cfg.Size).LRU().Build()
	Caches = append(Caches, CTICache)
	CacheNames = append(CacheNames, cfg.Name)
	CacheConfig = append(CacheConfig, cfg)
	return nil
}

//TBD : Prom metrics :
// - number of existing cache
// - individual cache size

func SetKey(cacheName string, key string, value string, expiration *time.Duration) error {

	for i, name := range CacheNames {
		if name == cacheName {
			if expiration == nil {
				expiration = &CacheConfig[i].TTL
			}
			if err := Caches[i].SetWithExpire(key, value, *expiration); err != nil {
				log.Warningf("While setting key %s in cache %s: %s", key, cacheName, err)
			}
		}
	}
	return nil
}

func GetKey(cacheName string, key string) (string, error) {
	for i, name := range CacheNames {
		if name == cacheName {
			if value, err := Caches[i].Get(key); err != nil {
				//do not warn or log if key not found
				if err == gcache.KeyNotFoundError {
					return "", nil
				}
				log.Warningf("While getting key %s in cache %s: %s", key, cacheName, err)
				return "", err
			} else {
				return value.(string), nil
			}
		}
	}
	log.Warningf("Cache %s not found", cacheName)
	return "", nil
}
