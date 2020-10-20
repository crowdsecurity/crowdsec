package v1

import (
	"fmt"
	"os"
	"time"

	"errors"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
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
		return "", errors.New(fmt.Sprintf("missing : %v", err.Error()))
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
		log.Printf("Error machine login : %+v ", err)
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

	//useragent := c.Request.UserAgent()

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
	secret := os.Getenv("SECRET")
	if secret == "" {
		secret = "crowdsecret"
	}
	jwtMiddleware := &JWT{
		DbClient: dbClient,
	}

	ret, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:           "Crowdsec API local",
		Key:             []byte(secret),
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
