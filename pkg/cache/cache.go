package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

var Caches []gcache.Cache
var CacheNames []string
var CacheConfig []CacheCfg

var MetricsRunning bool

/*prometheus*/
var CacheMetrics = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_cache_size",
		Help: "Entries per cache.",
	},
	[]string{"name", "type"},
)

// would it make sense to have a tomb ? seems overkill
func UpdateCacheMetrics() {
	tick := time.NewTicker(30 * time.Second)

	for range tick.C {
		for i, name := range CacheNames {
			CacheMetrics.With(prometheus.Labels{"name": name, "type": CacheConfig[i].Strategy}).Set(float64(Caches[i].Len(false)))
		}
	}
}

type CacheCfg struct {
	Name     string
	Size     int
	TTL      time.Duration
	Strategy string
	LogLevel *log.Level
	Logger   *log.Entry
}

func CacheInit(cfg CacheCfg) error {
	//not really thread safe, but we don't care
	if !MetricsRunning {
		MetricsRunning = true
		go UpdateCacheMetrics()
	}
	for _, name := range CacheNames {
		if name == cfg.Name {
			log.Infof("Cache %s already exists", cfg.Name)
		}
	}
	//get a default logger
	if cfg.LogLevel == nil {
		cfg.LogLevel = new(log.Level)
		*cfg.LogLevel = log.InfoLevel
	}
	var clog = logrus.New()
	if err := types.ConfigureLogger(clog); err != nil {
		log.Fatalf("While creating cache logger : %s", err)
	}
	clog.SetLevel(*cfg.LogLevel)
	cfg.Logger = clog.WithFields(log.Fields{
		"cache": cfg.Name,
	})

	tmpCache := gcache.New(cfg.Size)
	switch cfg.Strategy {
	case "LRU":
		tmpCache = tmpCache.LRU()
	case "LFU":
		tmpCache = tmpCache.LFU()
	case "ARC":
		tmpCache = tmpCache.ARC()
	default:
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
			if value, err := Caches[i].Get(key); err != nil {
				//do not warn or log if key not found
				if err == gcache.KeyNotFoundError {
					return "", nil
				}
				CacheConfig[i].Logger.Warningf("While getting key %s in cache %s: %s", key, cacheName, err)
				return "", err
			} else {
				return value.(string), nil
			}
		}
	}
	log.Warningf("Cache %s not found", cacheName)
	return "", nil
}
