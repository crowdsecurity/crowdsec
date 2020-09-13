package middlewares

import "github.com/crowdsecurity/crowdsec/pkg/database"

type Middlewares struct {
	APIKey *APIKey
	JWT    *JWT
}

func NewMiddlewares(dbClient *database.Client) (*Middlewares, error) {
	var err error

	ret := &Middlewares{}

	ret.JWT, err = NewJWT(dbClient)
	if err != nil {
		return &Middlewares{}, err
	}

	ret.APIKey = NewAPIKey(dbClient)

	return ret, nil
}
