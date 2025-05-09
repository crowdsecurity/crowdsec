package database

import (
	"context"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/configitem"
)

func (c *Client) GetConfigItem(ctx context.Context, key string) (string, error) {
	result, err := c.Ent.ConfigItem.Query().Where(configitem.NameEQ(key)).First(ctx)

	switch {
	case ent.IsNotFound(err):
		return "", nil
	case err != nil:
		return "", errors.Wrapf(QueryFail, "select config item: %s", err)
	default:
		return result.Value, nil
	}
}

func (c *Client) SetConfigItem(ctx context.Context, key string, value string) error {
	nbUpdated, err := c.Ent.ConfigItem.Update().SetValue(value).Where(configitem.NameEQ(key)).Save(ctx)

	switch {
	case ent.IsNotFound(err) || nbUpdated == 0:
		// not found, create
		err := c.Ent.ConfigItem.Create().SetName(key).SetValue(value).Exec(ctx)
		if err != nil {
			return errors.Wrapf(QueryFail, "insert config item: %s", err)
		}
	case err != nil:
		return errors.Wrapf(QueryFail, "update config item: %s", err)
	}

	return nil
}
