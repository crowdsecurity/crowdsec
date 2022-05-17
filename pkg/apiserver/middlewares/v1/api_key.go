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
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

var (
	APIKeyHeader = "X-Api-Key"
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
	return hex.EncodeToString(bytes), nil
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

func (a *APIKey) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		var bouncer *ent.Bouncer
		var err error

		if c.Request.TLS != nil && len(c.Request.TLS.PeerCertificates) > 0 {
			if a.TlsAuth == nil {
				log.WithField("ip", c.ClientIP()).Error("TLS Auth is not configured but client presented a certificate")
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
			validCert, extractedCN, err := a.TlsAuth.ValidateCert(c)
			if !validCert {
				log.WithField("ip", c.ClientIP()).Errorf("invalid client certificate: %s", err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
			if err != nil {
				log.WithField("ip", c.ClientIP()).Error(err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
			bouncerName := fmt.Sprintf("%s@%s", extractedCN, c.ClientIP())
			bouncer, err = a.DbClient.SelectBouncerByName(bouncerName)
			//This is likely not the proper way, but isNotFound does not seem to work
			if err != nil && strings.Contains(err.Error(), "bouncer not found") {
				//Because we have a valid cert, automatically create the bouncer in the database if it does not exist
				//Set a random API key, but it will never be used
				apiKey, err := GenerateAPIKey(64)
				if err != nil {
					log.WithFields(log.Fields{
						"ip": c.ClientIP(),
						"cn": extractedCN,
					}).Errorf("error generating mock api key: %s", err)
					c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
					c.Abort()
					return
				}
				log.WithFields(log.Fields{
					"ip": c.ClientIP(),
					"cn": extractedCN,
				}).Infof("Creating bouncer %s", bouncerName)
				bouncer, err = a.DbClient.CreateBouncer(bouncerName, c.ClientIP(), HashSHA512(apiKey), types.TlsAuthType)
				if err != nil {
					log.WithFields(log.Fields{
						"ip": c.ClientIP(),
						"cn": extractedCN,
					}).Errorf("creating bouncer db entry : %s", err)
					c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
					c.Abort()
					return
				}
			} else if err != nil {
				//error while selecting bouncer
				log.WithFields(log.Fields{
					"ip": c.ClientIP(),
					"cn": extractedCN,
				}).Errorf("while selecting bouncers: %s", err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			} else {
				//bouncer was found in DB
				if bouncer.AuthType != types.TlsAuthType {
					log.WithFields(log.Fields{
						"ip": c.ClientIP(),
						"cn": extractedCN,
					}).Errorf("bouncer isn't allowed to auth by TLS")
					c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
					c.Abort()
					return
				}
			}
		} else {
			//API Key Authentication
			val, ok := c.Request.Header[APIKeyHeader]
			if !ok {
				log.WithFields(log.Fields{
					"ip": c.ClientIP(),
				}).Errorf("API key not found")
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
			hashStr := HashSHA512(val[0])
			bouncer, err = a.DbClient.SelectBouncer(hashStr)
			if err != nil {
				log.WithFields(log.Fields{
					"ip": c.ClientIP(),
				}).Errorf("while fetching bouncer info: %s", err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
			if bouncer.AuthType != types.ApiKeyAuthType {
				log.WithFields(log.Fields{
					"ip": c.ClientIP(),
				}).Errorf("bouncer %s attempted to login using an API key but it is configured to auth with %s", bouncer.Name, bouncer.AuthType)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
		}

		if bouncer == nil {
			log.WithFields(log.Fields{
				"ip": c.ClientIP(),
			}).Errorf("bouncer not found")
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()
			return
		}

		//maybe we want to store the whole bouncer object in the context instead, this would avoid another db query
		//in StreamDecision
		c.Set("BOUNCER_NAME", bouncer.Name)
		c.Set("BOUNCER_HASHED_KEY", bouncer.APIKey)

		if bouncer.IPAddress == "" {
			err = a.DbClient.UpdateBouncerIP(c.ClientIP(), bouncer.ID)
			if err != nil {
				log.WithFields(log.Fields{
					"ip":   c.ClientIP(),
					"name": bouncer.Name,
				}).Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
		}

		if bouncer.IPAddress != c.ClientIP() && bouncer.IPAddress != "" {
			log.Warningf("new IP address detected for bouncer '%s': %s (old: %s)", bouncer.Name, c.ClientIP(), bouncer.IPAddress)
			err = a.DbClient.UpdateBouncerIP(c.ClientIP(), bouncer.ID)
			if err != nil {
				log.WithFields(log.Fields{
					"ip":   c.ClientIP(),
					"name": bouncer.Name,
				}).Errorf("Failed to update ip address for '%s': %s\n", bouncer.Name, err)
				c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
				c.Abort()
				return
			}
		}

		useragent := strings.Split(c.Request.UserAgent(), "/")

		if len(useragent) != 2 {
			log.WithFields(log.Fields{
				"ip":   c.ClientIP(),
				"name": bouncer.Name,
			}).Warningf("bad user agent '%s'", c.Request.UserAgent())
			useragent = []string{c.Request.UserAgent(), "N/A"}
		}

		if bouncer.Version != useragent[1] || bouncer.Type != useragent[0] {
			if err := a.DbClient.UpdateBouncerTypeAndVersion(useragent[0], useragent[1], bouncer.ID); err != nil {
				log.WithFields(log.Fields{
					"ip":   c.ClientIP(),
					"name": bouncer.Name,
				}).Errorf("failed to update bouncer version and type: %s", err)
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
