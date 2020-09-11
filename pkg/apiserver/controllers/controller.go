package controllers

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

type Controller struct {
	Ectx         context.Context
	DBClient     *database.Client
	APIKeyHeader string
}

func New(ctx context.Context, client *database.Client, APIKeyHeader string) *Controller {
	return &Controller{
		Ectx:         ctx,
		DBClient:     client,
		APIKeyHeader: APIKeyHeader,
	}
}
