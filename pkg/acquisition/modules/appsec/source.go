package appsecacquisition

import (
	"crypto/x509"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/allowlists"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type Source struct {
	config                Configuration
	hub                   *cwhub.Hub
	lapiClient            *apiclient.ApiClient
	lapiClientConfig      *csconfig.LocalApiClientCfg
	logger                *log.Entry
	mux                   *http.ServeMux
	server                *http.Server
	InChan                chan appsec.ParsedRequest
	AppsecRuntime         *appsec.AppsecRuntimeConfig
	AppsecConfigs         map[string]appsec.AppsecConfig
	lapiURL               string
	AuthCache             AuthCache
	AppsecRunners         []AppsecRunner // one for each go-routine
	appsecAllowlistClient *allowlists.AppsecAllowlist
	lapiCACertPool        *x509.CertPool
	authMutex             sync.Mutex
	httpClient            *http.Client
}

type AuthCache struct {
	APIKeys map[string]time.Time
	mu      sync.RWMutex
}

func NewAuthCache() AuthCache {
	return AuthCache{
		APIKeys: make(map[string]time.Time, 0),
		mu:      sync.RWMutex{},
	}
}

func (ac *AuthCache) Set(apiKey string, expiration time.Time) {
	ac.mu.Lock()
	ac.APIKeys[apiKey] = expiration
	ac.mu.Unlock()
}

func (ac *AuthCache) Get(apiKey string) (time.Time, bool) {
	ac.mu.RLock()
	expiration, exists := ac.APIKeys[apiKey]
	ac.mu.RUnlock()

	return expiration, exists
}

func (ac *AuthCache) Delete(apiKey string) {
	ac.mu.Lock()
	delete(ac.APIKeys, apiKey)
	ac.mu.Unlock()
}

func (w *Source) SetClientConfig(config *csconfig.LocalApiClientCfg) {
	w.lapiClientConfig = config
}

func (w *Source) SetHub(hub *cwhub.Hub) {
	w.hub = hub
}

func (w *Source) GetMode() string {
	return w.config.Mode
}

func (*Source) GetName() string {
	return "appsec"
}

func (*Source) CanRun() error {
	return nil
}

func (w *Source) GetUuid() string {
	return w.config.UniqueId
}

func (w *Source) Dump() any {
	return w
}
