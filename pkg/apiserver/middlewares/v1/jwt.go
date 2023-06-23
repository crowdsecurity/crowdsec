package v1

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var identityKey = "id"

type JWT struct {
	Middleware *jwt.GinJWTMiddleware
	DbClient   *database.Client
	TlsAuth    *TLSAuth
}

func PayloadFunc(data interface{}) jwt.MapClaims {
	if value, ok := data.(*models.WatcherAuthRequest); ok {
		return jwt.MapClaims{
			identityKey: &value.MachineID,
		}
	}
	return jwt.MapClaims{}
}

func IdentityHandler(c *gin.Context) interface{} {
	claims := jwt.ExtractClaims(c)
	machineId := claims[identityKey].(string)
	return &models.WatcherAuthRequest{
		MachineID: &machineId,
	}
}

func (j *JWT) Authenticator(c *gin.Context) (interface{}, error) {
	var loginInput models.WatcherAuthRequest
	var scenarios string
	var err error
	var scenariosInput []string
	var clientMachine *ent.Machine
	var machineID string

	if c.Request.TLS != nil && len(c.Request.TLS.PeerCertificates) > 0 {
		if j.TlsAuth == nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()
			return nil, errors.New("TLS auth is not configured")
		}
		validCert, extractedCN, err := j.TlsAuth.ValidateCert(c)
		if err != nil {
			log.Error(err)
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()
			return nil, errors.Wrap(err, "while trying to validate client cert")
		}
		if !validCert {
			c.JSON(http.StatusForbidden, gin.H{"message": "access forbidden"})
			c.Abort()
			return nil, fmt.Errorf("failed cert authentication")
		}

		machineID = fmt.Sprintf("%s@%s", extractedCN, c.ClientIP())
		clientMachine, err = j.DbClient.Ent.Machine.Query().
			Where(machine.MachineId(machineID)).
			First(j.DbClient.CTX)
		if ent.IsNotFound(err) {
			//Machine was not found, let's create it
			log.Printf("machine %s not found, create it", machineID)
			//let's use an apikey as the password, doesn't matter in this case (generatePassword is only available in cscli)
			pwd, err := GenerateAPIKey(dummyAPIKeySize)
			if err != nil {
				log.WithFields(log.Fields{
					"ip": c.ClientIP(),
					"cn": extractedCN,
				}).Errorf("error generating password: %s", err)
				return nil, fmt.Errorf("error generating password")
			}
			password := strfmt.Password(pwd)
			clientMachine, err = j.DbClient.CreateMachine(&machineID, &password, "", true, true, types.TlsAuthType)
			if err != nil {
				return "", errors.Wrapf(err, "while creating machine entry for %s", machineID)
			}
		} else if err != nil {
			return "", errors.Wrapf(err, "while selecting machine entry for %s", machineID)
		} else {
			if clientMachine.AuthType != types.TlsAuthType {
				return "", errors.Errorf("machine %s attempted to auth with TLS cert but it is configured to use %s", machineID, clientMachine.AuthType)
			}
			machineID = clientMachine.MachineId
			loginInput := struct {
				Scenarios []string `json:"scenarios"`
			}{
				Scenarios: []string{},
			}
			err := c.ShouldBindJSON(&loginInput)
			if err != nil {
				return "", errors.Wrap(err, "missing scenarios list in login request for TLS auth")
			}
			scenariosInput = loginInput.Scenarios
		}

	} else {
		//normal auth

		if err := c.ShouldBindJSON(&loginInput); err != nil {
			return "", errors.Wrap(err, "missing")
		}
		if err := loginInput.Validate(strfmt.Default); err != nil {
			return "", errors.New("input format error")
		}
		machineID = *loginInput.MachineID
		password := *loginInput.Password
		scenariosInput = loginInput.Scenarios

		clientMachine, err = j.DbClient.Ent.Machine.Query().
			Where(machine.MachineId(machineID)).
			First(j.DbClient.CTX)
		if err != nil {
			log.Printf("Error machine login for %s : %+v ", machineID, err)
			return nil, err
		}

		if clientMachine == nil {
			log.Errorf("Nothing for '%s'", machineID)
			return nil, jwt.ErrFailedAuthentication
		}

		if clientMachine.AuthType != types.PasswordAuthType {
			return nil, errors.Errorf("machine %s attempted to auth with password but it is configured to use %s", machineID, clientMachine.AuthType)
		}

		if !clientMachine.IsValidated {
			return nil, fmt.Errorf("machine %s not validated", machineID)
		}

		if err = bcrypt.CompareHashAndPassword([]byte(clientMachine.Password), []byte(password)); err != nil {
			return nil, jwt.ErrFailedAuthentication
		}

		//end of normal auth
	}

	if len(scenariosInput) > 0 {
		for _, scenario := range scenariosInput {
			if scenarios == "" {
				scenarios = scenario
			} else {
				scenarios += "," + scenario
			}
		}
		err = j.DbClient.UpdateMachineScenarios(scenarios, clientMachine.ID)
		if err != nil {
			log.Errorf("Failed to update scenarios list for '%s': %s\n", machineID, err)
			return nil, jwt.ErrFailedAuthentication
		}
	}

	if clientMachine.IpAddress == "" {
		err = j.DbClient.UpdateMachineIP(c.ClientIP(), clientMachine.ID)
		if err != nil {
			log.Errorf("Failed to update ip address for '%s': %s\n", machineID, err)
			return nil, jwt.ErrFailedAuthentication
		}
	}

	if clientMachine.IpAddress != c.ClientIP() && clientMachine.IpAddress != "" {
		log.Warningf("new IP address detected for machine '%s': %s (old: %s)", clientMachine.MachineId, c.ClientIP(), clientMachine.IpAddress)
		err = j.DbClient.UpdateMachineIP(c.ClientIP(), clientMachine.ID)
		if err != nil {
			log.Errorf("Failed to update ip address for '%s': %s\n", clientMachine.MachineId, err)
			return nil, jwt.ErrFailedAuthentication
		}
	}

	useragent := strings.Split(c.Request.UserAgent(), "/")
	if len(useragent) != 2 {
		log.Warningf("bad user agent '%s' from '%s'", c.Request.UserAgent(), c.ClientIP())
		return nil, jwt.ErrFailedAuthentication
	}

	if err := j.DbClient.UpdateMachineVersion(useragent[1], clientMachine.ID); err != nil {
		log.Errorf("unable to update machine '%s' version '%s': %s", clientMachine.MachineId, useragent[1], err)
		log.Errorf("bad user agent from : %s", c.ClientIP())
		return nil, jwt.ErrFailedAuthentication
	}
	return &models.WatcherAuthRequest{
		MachineID: &machineID,
	}, nil

}

func Authorizator(data interface{}, c *gin.Context) bool {
	return true
}

func Unauthorized(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
}

func randomSecret() ([]byte, error) {
	size := 64
	secret := make([]byte, size)

	n, err := rand.Read(secret)
	if err != nil {
		return nil, errors.New("unable to generate a new random seed for JWT generation")
	}

	if n != size {
		return nil, errors.New("not enough entropy at random seed generation for JWT generation")
	}

	return secret, nil
}

func NewJWT(dbClient *database.Client) (*JWT, error) {
	// Get secret from environment variable "SECRET"
	var (
		secret []byte
		err    error
	)

	// Please be aware that brute force HS256 is possible.
	// PLEASE choose a STRONG secret
	secretString := os.Getenv("CS_LAPI_SECRET")
	secret = []byte(secretString)

	switch l := len(secret); {
	case l == 0:
		secret, err = randomSecret()
		if err != nil {
			return &JWT{}, err
		}
	case l < 64:
		return &JWT{}, errors.New("CS_LAPI_SECRET not strong enough")
	}

	jwtMiddleware := &JWT{
		DbClient: dbClient,
		TlsAuth:  &TLSAuth{},
	}

	ret, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:           "Crowdsec API local",
		Key:             secret,
		Timeout:         time.Hour,
		MaxRefresh:      time.Hour,
		IdentityKey:     identityKey,
		PayloadFunc:     PayloadFunc,
		IdentityHandler: IdentityHandler,
		Authenticator:   jwtMiddleware.Authenticator,
		Authorizator:    Authorizator,
		Unauthorized:    Unauthorized,
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,
	})
	if err != nil {
		return &JWT{}, err
	}

	errInit := ret.MiddlewareInit()
	if errInit != nil {
		return &JWT{}, fmt.Errorf("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}
	jwtMiddleware.Middleware = ret

	return jwtMiddleware, nil
}
