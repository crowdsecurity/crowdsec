package database

import (
	"context"
	"fmt"

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
	err := c.Ent.ConfigItem.
		Create().
		SetName(key).
		SetValue(value).
		OnConflictColumns(configitem.FieldName).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("insert/update config item: %w", err)
	}

	return nil
}
