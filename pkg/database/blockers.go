package database

import (
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/blocker"
	"github.com/pkg/errors"
)

func (c *Client) LastBlockerPull(apiKey string) (string, error) {
	result, err := c.Ent.Blocker.Query().Where(blocker.APIKeyEQ(apiKey)).Select(blocker.FieldLastPull).Strings(c.CTX)
	if err != nil {
		return "", errors.Wrap(QueryFail, "can't get last blocker pull")
	}

	return result[0], nil
}
