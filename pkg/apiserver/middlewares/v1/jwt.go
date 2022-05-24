package v1

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
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
	if err := c.ShouldBindJSON(&loginInput); err != nil {
		return "", errors.Wrap(err, "missing")
	}
	if err := loginInput.Validate(strfmt.Default); err != nil {
		return "", errors.New("input format error")
	}
	machineID := *loginInput.MachineID
	password := *loginInput.Password
	scenariosInput := loginInput.Scenarios

	machine, err := j.DbClient.Ent.Machine.Query().
		Where(machine.MachineId(machineID)).
		First(j.DbClient.CTX)
	if err != nil {
		log.Printf("Error machine login for %s : %+v ", machineID, err)
		return nil, err
	}

	if machine == nil {
		log.Errorf("Nothing for '%s'", machineID)
		return nil, jwt.ErrFailedAuthentication
	}

	if !machine.IsValidated {
		return nil, fmt.Errorf("machine %s not validated", machineID)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(machine.Password), []byte(password)); err != nil {
		return nil, jwt.ErrFailedAuthentication
	}

	if len(scenariosInput) > 0 {
		for _, scenario := range scenariosInput {
			if scenarios == "" {
				scenarios = scenario
			} else {
				scenarios += "," + scenario
			}
		}
		err = j.DbClient.UpdateMachineScenarios(scenarios, machine.ID)
		if err != nil {
			log.Errorf("Failed to update scenarios list for '%s': %s\n", machineID, err)
			return nil, jwt.ErrFailedAuthentication
		}
	}

	if machine.IpAddress == "" {
		err = j.DbClient.UpdateMachineIP(c.ClientIP(), machine.ID)
		if err != nil {
			log.Errorf("Failed to update ip address for '%s': %s\n", machineID, err)
			return nil, jwt.ErrFailedAuthentication
		}
	}

	if machine.IpAddress != c.ClientIP() && machine.IpAddress != "" {
		log.Warningf("new IP address detected for machine '%s': %s (old: %s)", machine.MachineId, c.ClientIP(), machine.IpAddress)
		err = j.DbClient.UpdateMachineIP(c.ClientIP(), machine.ID)
		if err != nil {
			log.Errorf("Failed to update ip address for '%s': %s\n", machine.MachineId, err)
			return nil, jwt.ErrFailedAuthentication
		}
	}

	useragent := strings.Split(c.Request.UserAgent(), "/")
	if len(useragent) != 2 {
		log.Warningf("bad user agent '%s' from '%s'", c.Request.UserAgent(), c.ClientIP())
		return nil, jwt.ErrFailedAuthentication
	}

	if err := j.DbClient.UpdateMachineVersion(useragent[1], machine.ID); err != nil {
		log.Errorf("unable to update machine '%s' version '%s': %s", machine.MachineId, useragent[1], err)
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

func NewJWT(dbClient *database.Client) (*JWT, error) {
	// Get secret from environment variable "SECRET"
	var (
		secret []byte
	)

	//Please be aware that brute force HS256 is possible.
	//PLEASE choose a STRONG secret
	secret_string := os.Getenv("CS_LAPI_SECRET")
	if secret_string == "" {
		secret = make([]byte, 64)
		if n, err := rand.Read(secret); err != nil {
			log.Fatalf("unable to generate a new random seed for JWT generation")
		} else {
			if n != 64 {
				log.Fatalf("not enough entropy at random seed generation for JWT generation")
			}
		}
	} else {
		secret = []byte(secret_string)
		if len(secret) < 64 {
			log.Fatalf("secret not strong enough")
		}
	}

	jwtMiddleware := &JWT{
		DbClient: dbClient,
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

	errInit := ret.MiddlewareInit()
	if errInit != nil {
		return &JWT{}, fmt.Errorf("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	if err != nil {
		return &JWT{}, err
	}

	return &JWT{Middleware: ret}, nil
}
