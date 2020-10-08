package middlewares

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"

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
		bouncer, err := a.DbClient.SelectBlocker(hashStr)
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

		if bouncer.IPAddress == "" {
			err = a.DbClient.UpdateBlockerIP(c.ClientIP(), bouncer.ID)
			if err != nil {
				log.Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
		}
		if bouncer.IPAddress != c.ClientIP() && bouncer.IPAddress != "" {
			log.Warningf("new IP address detected for bouncer '%s': %s (old: %s)", bouncer.Name, c.ClientIP(), bouncer.IPAddress)
			err = a.DbClient.UpdateBlockerIP(c.ClientIP(), bouncer.ID)
			if err != nil {
				log.Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
