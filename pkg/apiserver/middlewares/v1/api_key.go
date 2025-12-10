package v1

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	APIKeyHeader      = "X-Api-Key"
	BouncerContextKey = "bouncer_info"
	dummyAPIKeySize   = 54
	// max allowed by bcrypt 72 = 54 bytes in base64
)

type APIKey struct {
	HeaderName string
	DbClient   *database.Client
	TlsAuth    *TLSAuth
}

// baseBouncerName removes any trailing "@<ip>" segments from a bouncer's name.
//
// When a bouncer changes its IP address, it is detected by LAPI as a new bouncer,
// to allow for key sharing. LAPI then creates a new DB entry by appending "@<ip>"
// to the existing name. If the existing name already ends with "@<ip>", this can lead to
// chained names like "my-bouncer@1.2.3.4@5.6.7.8". To prevent runaway suffixes,
// this helper repeatedly strips the final "@<ip>" token until no valid IPv4/IPv6
// address remains, returning the "base" bouncer name.
func baseBouncerName(name string) string {
    for {
        i := strings.LastIndexByte(name, '@')
        if i < 0 {
            return name
        }

        tail := name[i+1:]
        if _, err := netip.ParseAddr(tail); err == nil {
            name = name[:i]
            continue
        }

        return name
    }
}

func GenerateAPIKey(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(bytes)

	// the '=' can cause issues on some bouncers
	return strings.TrimRight(encoded, "="), nil
}

func NewAPIKey(dbClient *database.Client) *APIKey {
	return &APIKey{
		HeaderName: APIKeyHeader,
		DbClient:   dbClient,
		TlsAuth:    &TLSAuth{},
	}
}

func HashSHA512(str string) string {
	hashedKey := sha512.New()
	hashedKey.Write([]byte(str))

	hashStr := fmt.Sprintf("%x", hashedKey.Sum(nil))

	return hashStr
}

func (a *APIKey) authTLS(r *http.Request, clientIP string, logger *log.Entry) *ent.Bouncer {
	if a.TlsAuth == nil {
		logger.Warn("TLS Auth is not configured but client presented a certificate")
		return nil
	}

	ctx := r.Context()

	extractedCN, err := a.TlsAuth.ValidateCertFromRequest(r)
	if err != nil {
		logger.Warn(err)
		return nil
	}

	logger = logger.WithField("cn", extractedCN)

	bouncerName := fmt.Sprintf("%s@%s", extractedCN, clientIP)
	bouncer, err := a.DbClient.SelectBouncerByName(ctx, bouncerName)

	// This is likely not the proper way, but isNotFound does not seem to work
	if err != nil && strings.Contains(err.Error(), "bouncer not found") {
		// Because we have a valid cert, automatically create the bouncer in the database if it does not exist
		// Set a random API key, but it will never be used
		apiKey, err := GenerateAPIKey(dummyAPIKeySize)
		if err != nil {
			logger.Errorf("error generating mock api key: %s", err)
			return nil
		}

		logger.Infof("Creating bouncer %s", bouncerName)

		bouncer, err = a.DbClient.CreateBouncer(ctx, bouncerName, clientIP, HashSHA512(apiKey), types.TlsAuthType, true)
		if err != nil {
			logger.Errorf("while creating bouncer db entry: %s", err)
			return nil
		}
	} else if err != nil {
		// error while selecting bouncer
		logger.Errorf("while selecting bouncers: %s", err)
		return nil
	} else if bouncer.AuthType != types.TlsAuthType {
		// bouncer was found in DB
		logger.Errorf("bouncer isn't allowed to auth by TLS")
		return nil
	}

	return bouncer
}

func (a *APIKey) authPlain(r *http.Request, clientIP string, logger *log.Entry) *ent.Bouncer {
	val, ok := r.Header[APIKeyHeader]
	if !ok {
		logger.Errorf("API key not found")
		return nil
	}

	ctx := r.Context()

	hashStr := HashSHA512(val[0])

	// Appsec case, we only care if the key is valid
	// No content is returned, no last_pull update or anything
	if r.Method == http.MethodHead {
		bouncer, err := a.DbClient.SelectBouncers(ctx, hashStr, types.ApiKeyAuthType)
		if err != nil {
			logger.Errorf("while fetching bouncer info: %s", err)
			return nil
		}

		if len(bouncer) == 0 {
			logger.Debugf("no bouncer found with this key")
			return nil
		}

		return bouncer[0]
	}

	// most common case, check if this specific bouncer exists
	bouncer, err := a.DbClient.SelectBouncerWithIP(ctx, hashStr, clientIP)
	if err != nil && !ent.IsNotFound(err) {
		logger.Errorf("while fetching bouncer info: %s", err)
		return nil
	}

	// We found the bouncer with key and IP, we can use it
	if bouncer != nil {
		if bouncer.AuthType != types.ApiKeyAuthType {
			logger.Errorf("bouncer isn't allowed to auth by API key")
			return nil
		}

		return bouncer
	}

	// We didn't find the bouncer with key and IP, let's try to find it with the key only
	bouncers, err := a.DbClient.SelectBouncers(ctx, hashStr, types.ApiKeyAuthType)
	if err != nil {
		logger.Errorf("while fetching bouncer info: %s", err)
		return nil
	}

	if len(bouncers) == 0 {
		logger.Debugf("no bouncer found with this key")
		return nil
	}

	logger.Debugf("found %d bouncers with this key", len(bouncers))

	// We only have one bouncer with this key and no IP
	// This is the first request made by this bouncer, keep this one
	if len(bouncers) == 1 && bouncers[0].IPAddress == "" {
		return bouncers[0]
	}

	// Bouncers are ordered by ID, first one *should* be the manually created one
	// Can probably get a bit weird if the user deletes the manually created one
	base := baseBouncerName(bouncers[0].Name)
	bouncerName := fmt.Sprintf("%s@%s", base, clientIP)

	logger.Infof("Creating bouncer %s", bouncerName)

	bouncer, err = a.DbClient.CreateBouncer(ctx, bouncerName, clientIP, hashStr, types.ApiKeyAuthType, true)
	if err != nil {
		logger.Errorf("while creating bouncer db entry: %s", err)
		return nil
	}

	return bouncer
}

// MiddlewareFunc returns a middleware that validates API keys
func (a *APIKey) MiddlewareFunc() router.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var bouncer *ent.Bouncer

			ctx := r.Context()
			clientIP := router.GetClientIP(r) // Gets IP from context (resolved by ClientIPMiddleware)

			logger := log.WithField("ip", clientIP)

			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				bouncer = a.authTLS(r, clientIP, logger)
			} else {
				bouncer = a.authPlain(r, clientIP, logger)
			}

			if bouncer == nil {
				router.AbortWithJSON(w, http.StatusForbidden, map[string]string{"message": "access forbidden"})
				return
			}

			// Appsec request, return immediately if we found something
			if r.Method == http.MethodHead {
				// Store bouncer in context and continue
				ctx = router.SetContextValue(r, BouncerContextKey, bouncer).Context()
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			logger = logger.WithField("name", bouncer.Name)

			// 1st time we see this bouncer, we update its IP
			if bouncer.IPAddress == "" {
				if err := a.DbClient.UpdateBouncerIP(ctx, clientIP, bouncer.ID); err != nil {
					logger.Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
					router.AbortWithJSON(w, http.StatusForbidden, map[string]string{"message": "access forbidden"})
					return
				}
			}

			useragent := strings.Split(r.UserAgent(), "/")
			if len(useragent) != 2 {
				logger.Warningf("bad user agent '%s'", r.UserAgent())
				useragent = []string{r.UserAgent(), "N/A"}
			}

			if bouncer.Version != useragent[1] || bouncer.Type != useragent[0] {
				if err := a.DbClient.UpdateBouncerTypeAndVersion(ctx, useragent[0], useragent[1], bouncer.ID); err != nil {
					logger.Errorf("failed to update bouncer version and type: %s", err)
					router.AbortWithJSON(w, http.StatusForbidden, map[string]string{"message": "bad user agent"})
					return
				}
			}

			// Store bouncer in context
			ctx = router.SetContextValue(r, BouncerContextKey, bouncer).Context()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
