package v1

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

var (
	APIKeyHeader = "X-Api-Key"
)

type APIKey struct {
	HeaderName string
	DbClient   *database.Client
}

func GenerateAPIKey(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func NewAPIKey(dbClient *database.Client) *APIKey {
	return &APIKey{
		HeaderName: APIKeyHeader,
		DbClient:   dbClient,
	}
}

func HashSHA512(str string) string {
	hashedKey := sha512.New()
	hashedKey.Write([]byte(str))

	hashStr := fmt.Sprintf("%x", hashedKey.Sum(nil))

	return hashStr
}

func (a *APIKey) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		val, ok := c.Request.Header[APIKeyHeader]
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()
			return
		}

		hashStr := HashSHA512(val[0])
		bouncer, err := a.DbClient.SelectBouncer(hashStr)
		if err != nil {
			log.Errorf("auth api key error: %s", err)
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()
			return
		}

		if bouncer == nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()
			return
		}

		c.Set("BOUNCER_NAME", bouncer.Name)

		if bouncer.IPAddress == "" {
			err = a.DbClient.UpdateBouncerIP(c.ClientIP(), bouncer.ID)
			if err != nil {
				log.Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
		}

		if bouncer.IPAddress != c.ClientIP() && bouncer.IPAddress != "" {
			log.Warningf("new IP address detected for bouncer '%s': %s (old: %s)", bouncer.Name, c.ClientIP(), bouncer.IPAddress)
			err = a.DbClient.UpdateBouncerIP(c.ClientIP(), bouncer.ID)
			if err != nil {
				log.Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
		}

		useragent := strings.Split(c.Request.UserAgent(), "/")

		if len(useragent) != 2 {
			log.Warningf("bad user agent '%s' from '%s'", c.Request.UserAgent(), c.ClientIP())
			useragent = []string{c.Request.UserAgent(), "N/A"}
		}

		if bouncer.Version != useragent[1] || bouncer.Type != useragent[0] {
			if err := a.DbClient.UpdateBouncerTypeAndVersion(useragent[0], useragent[1], bouncer.ID); err != nil {
				log.Errorf("failed to update bouncer version and type from '%s' (%s): %s", c.Request.UserAgent(), c.ClientIP(), err)
				c.JSON(http.StatusForbidden, gin.H{"message": "bad user agent"})
				c.Abort()
				return
			}
		}

		if c.Request.Method != "HEAD" && time.Now().UTC().Sub(bouncer.LastPull) >= time.Minute {
			if err := a.DbClient.UpdateBouncerLastPull(time.Now().UTC(), bouncer.ID); err != nil {
				log.Errorf("failed to update bouncer last pull: %v", err)
			}
		}

		c.Next()
	}
}
