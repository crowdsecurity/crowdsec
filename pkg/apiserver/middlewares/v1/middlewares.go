package v1

import "github.com/crowdsecurity/crowdsec/pkg/database"

type Middlewares struct {
	APIKey *APIKey
	JWT    *JWT
}

func NewMiddlewares(dbClient *database.Client, AllowedAgentsOU []string, AllowedBouncersOU []string) (*Middlewares, error) {
	var err error

	ret := &Middlewares{}

	ret.JWT, err = NewJWT(dbClient, AllowedAgentsOU)
	if err != nil {
		return &Middlewares{}, err
	}

	ret.APIKey = NewAPIKey(dbClient, AllowedBouncersOU)
	return ret, nil
}
