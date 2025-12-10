package cache

import (
	"errors"
	"time"

	"github.com/bluele/gcache"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/logging"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

var (
	Caches      = []gcache.Cache{}
	CacheNames  []string
	CacheConfig = []CacheCfg{}
)

// UpdateCacheMetrics is called directly by the prom handler
func UpdateCacheMetrics() {
	metrics.CacheMetrics.Reset()

	for i, name := range CacheNames {
		metrics.CacheMetrics.With(prometheus.Labels{"name": name, "type": CacheConfig[i].Strategy}).Set(float64(Caches[i].Len(false)))
	}
}

type CacheCfg struct {
	Name     string
	Size     int
	TTL      time.Duration
	Strategy string
	LogLevel log.Level
	Logger   log.FieldLogger
}

func (cfg CacheCfg) NewLogger() *log.Entry {
	clog := logging.SubLogger(log.StandardLogger(), "cache", cfg.LogLevel)
	return clog.WithField("cache", cfg.Name)
}

func CacheInit(cfg CacheCfg, logger log.FieldLogger) error {
	if logger == nil {
		logger = log.StandardLogger()
	}

	cfg.Logger = logger

	for _, name := range CacheNames {
		if name == cfg.Name {
			log.Infof("Cache %s already exists", cfg.Name)
		}
	}

	tmpCache := gcache.New(cfg.Size)

	switch cfg.Strategy {
	case "LRU":
		tmpCache = tmpCache.LRU()
	case "LFU":
		tmpCache = tmpCache.LFU()
	case "ARC":
		tmpCache = tmpCache.ARC()
	default:
		cfg.Strategy = "LRU"
		tmpCache = tmpCache.LRU()
	}

	CTICache := tmpCache.Build()
	Caches = append(Caches, CTICache)
	CacheNames = append(CacheNames, cfg.Name)
	CacheConfig = append(CacheConfig, cfg)

	return nil
}

func SetKey(cacheName string, key string, value string, expiration *time.Duration) error {
	for i, name := range CacheNames {
		if name == cacheName {
			if expiration == nil {
				expiration = &CacheConfig[i].TTL
			}

			CacheConfig[i].Logger.Debugf("Setting key %s to %s with expiration %v", key, value, *expiration)

			if err := Caches[i].SetWithExpire(key, value, *expiration); err != nil {
				CacheConfig[i].Logger.Warningf("While setting key %s in cache %s: %s", key, cacheName, err)
			}
		}
	}

	return nil
}

func GetKey(cacheName string, key string) (string, error) {
	for i, name := range CacheNames {
		if name == cacheName {
			value, err := Caches[i].Get(key)
			if err != nil {
				// do not warn or log if key not found
				if errors.Is(err, gcache.KeyNotFoundError) {
					return "", nil
				}
				CacheConfig[i].Logger.Warningf("While getting key %s in cache %s: %s", key, cacheName, err)

				return "", err
			}

			return value.(string), nil
		}
	}

	log.Warningf("Cache %s not found", cacheName)

	return "", nil
}
