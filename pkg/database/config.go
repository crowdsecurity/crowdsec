package database

import (
	"context"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/configitem"
)

func (c *Client) GetConfigItem(ctx context.Context, key string) (*string, error) {
	result, err := c.Ent.ConfigItem.Query().Where(configitem.NameEQ(key)).First(ctx)
	if err != nil && ent.IsNotFound(err) {
		return nil, nil
	}

	if err != nil {
		return nil, errors.Wrapf(QueryFail, "select config item: %s", err)
	}

	return &result.Value, nil
}

func (c *Client) SetConfigItem(ctx context.Context, key string, value string) error {
	nbUpdated, err := c.Ent.ConfigItem.Update().SetValue(value).Where(configitem.NameEQ(key)).Save(ctx)
	if (err != nil && ent.IsNotFound(err)) || nbUpdated == 0 { // not found, create
		err := c.Ent.ConfigItem.Create().SetName(key).SetValue(value).Exec(ctx)
		if err != nil {
			return errors.Wrapf(QueryFail, "insert config item: %s", err)
		}
	} else if err != nil {
		return errors.Wrapf(QueryFail, "update config item: %s", err)
	}

	return nil
}
