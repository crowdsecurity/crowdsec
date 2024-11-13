package v1

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

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

func (a *APIKey) authTLS(c *gin.Context, logger *log.Entry) *ent.Bouncer {
	if a.TlsAuth == nil {
		logger.Warn("TLS Auth is not configured but client presented a certificate")
		return nil
	}

	ctx := c.Request.Context()

	extractedCN, err := a.TlsAuth.ValidateCert(c)
	if err != nil {
		logger.Warn(err)
		return nil
	}

	logger = logger.WithField("cn", extractedCN)

	bouncerName := fmt.Sprintf("%s@%s", extractedCN, c.ClientIP())
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

		bouncer, err = a.DbClient.CreateBouncer(ctx, bouncerName, c.ClientIP(), HashSHA512(apiKey), types.TlsAuthType)
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

func (a *APIKey) authPlain(c *gin.Context, logger *log.Entry) *ent.Bouncer {
	val, ok := c.Request.Header[APIKeyHeader]
	if !ok {
		logger.Errorf("API key not found")
		return nil
	}

	ctx := c.Request.Context()

	hashStr := HashSHA512(val[0])

	bouncer, err := a.DbClient.SelectBouncer(ctx, hashStr)
	if err != nil {
		logger.Errorf("while fetching bouncer info: %s", err)
		return nil
	}

	if bouncer.AuthType != types.ApiKeyAuthType {
		logger.Errorf("bouncer %s attempted to login using an API key but it is configured to auth with %s", bouncer.Name, bouncer.AuthType)
		return nil
	}

	return bouncer
}

func (a *APIKey) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		var bouncer *ent.Bouncer

		ctx := c.Request.Context()

		clientIP := c.ClientIP()

		logger := log.WithField("ip", clientIP)

		if c.Request.TLS != nil && len(c.Request.TLS.PeerCertificates) > 0 {
			bouncer = a.authTLS(c, logger)
		} else {
			bouncer = a.authPlain(c, logger)
		}

		if bouncer == nil {
			// XXX: StatusUnauthorized?
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()

			return
		}

		logger = logger.WithField("name", bouncer.Name)

		if bouncer.IPAddress == "" {
			if err := a.DbClient.UpdateBouncerIP(ctx, clientIP, bouncer.ID); err != nil {
				logger.Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()

				return
			}
		}

		// Don't update IP on HEAD request, as it's used by the appsec to check the validity of the API key provided
		if bouncer.IPAddress != clientIP && bouncer.IPAddress != "" && c.Request.Method != http.MethodHead {
			log.Warningf("new IP address detected for bouncer '%s': %s (old: %s)", bouncer.Name, clientIP, bouncer.IPAddress)

			if err := a.DbClient.UpdateBouncerIP(ctx, clientIP, bouncer.ID); err != nil {
				logger.Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()

				return
			}
		}

		useragent := strings.Split(c.Request.UserAgent(), "/")
		if len(useragent) != 2 {
			logger.Warningf("bad user agent '%s'", c.Request.UserAgent())
			useragent = []string{c.Request.UserAgent(), "N/A"}
		}

		if bouncer.Version != useragent[1] || bouncer.Type != useragent[0] {
			if err := a.DbClient.UpdateBouncerTypeAndVersion(ctx, useragent[0], useragent[1], bouncer.ID); err != nil {
				logger.Errorf("failed to update bouncer version and type: %s", err)
				c.JSON(http.StatusForbidden, gin.H{"message": "bad user agent"})
				c.Abort()

				return
			}
		}

		c.Set(BouncerContextKey, bouncer)
	}
}
