package database

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/allowlist"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/allowlistitem"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func (c *Client) CreateAllowList(ctx context.Context, name string, description string, allowlistID string, fromConsole bool) (*ent.AllowList, error) {
	allowlist, err := c.Ent.AllowList.Create().
		SetName(name).
		SetFromConsole(fromConsole).
		SetDescription(description).
		SetAllowlistID(allowlistID).
		Save(ctx)
	if err != nil {
		if sqlgraph.IsUniqueConstraintError(err) {
			return nil, fmt.Errorf("allowlist '%s' already exists", name)
		}

		return nil, fmt.Errorf("unable to create allowlist: %w", err)
	}

	return allowlist, nil
}

func (c *Client) DeleteAllowList(ctx context.Context, name string, fromConsole bool) error {
	nbDeleted, err := c.Ent.AllowListItem.Delete().Where(allowlistitem.HasAllowlistWith(allowlist.NameEQ(name), allowlist.FromConsoleEQ(fromConsole))).Exec(ctx)
	if err != nil {
		return fmt.Errorf("unable to delete allowlist items: %w", err)
	}

	c.Log.Debugf("deleted %d items from allowlist %s", nbDeleted, name)

	nbDeleted, err = c.Ent.AllowList.
		Delete().
		Where(allowlist.NameEQ(name), allowlist.FromConsoleEQ(fromConsole)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("unable to delete allowlist: %w", err)
	}

	if nbDeleted == 0 {
		return fmt.Errorf("allowlist %s not found", name)
	}

	return nil
}

func (c *Client) DeleteAllowListByID(ctx context.Context, name string, allowlistID string, fromConsole bool) error {
	nbDeleted, err := c.Ent.AllowListItem.Delete().Where(allowlistitem.HasAllowlistWith(allowlist.AllowlistIDEQ(allowlistID), allowlist.FromConsoleEQ(fromConsole))).Exec(ctx)
	if err != nil {
		return fmt.Errorf("unable to delete allowlist items: %w", err)
	}

	c.Log.Debugf("deleted %d items from allowlist %s", nbDeleted, name)

	nbDeleted, err = c.Ent.AllowList.
		Delete().
		Where(allowlist.AllowlistIDEQ(allowlistID), allowlist.FromConsoleEQ(fromConsole)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("unable to delete allowlist: %w", err)
	}

	if nbDeleted == 0 {
		return fmt.Errorf("allowlist %s not found", name)
	}

	return nil
}

func (c *Client) ListAllowLists(ctx context.Context, withContent bool) ([]*ent.AllowList, error) {
	q := c.Ent.AllowList.Query()
	if withContent {
		q = q.WithAllowlistItems()
	}

	result, err := q.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to list allowlists: %w", err)
	}

	return result, nil
}

func (c *Client) GetAllowList(ctx context.Context, name string, withContent bool) (*ent.AllowList, error) {
	q := c.Ent.AllowList.Query().Where(allowlist.NameEQ(name))
	if withContent {
		q = q.WithAllowlistItems()
	}

	result, err := q.First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("allowlist '%s' not found", name)
		}

		return nil, err
	}

	return result, nil
}

func (c *Client) GetAllowListByID(ctx context.Context, allowlistID string, withContent bool) (*ent.AllowList, error) {
	q := c.Ent.AllowList.Query().Where(allowlist.AllowlistIDEQ(allowlistID))
	if withContent {
		q = q.WithAllowlistItems()
	}

	result, err := q.First(ctx)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) AddToAllowlist(ctx context.Context, list *ent.AllowList, items []*models.AllowlistItem) (int, error) {
	added := 0

	c.Log.Debugf("adding %d values to allowlist %s", len(items), list.Name)
	c.Log.Tracef("values: %+v", items)

	txClient, err := c.Ent.Tx(ctx)
	if err != nil {
		return 0, fmt.Errorf("error creating transaction: %w", err)
	}

	for _, item := range items {
		c.Log.Debugf("adding value %s to allowlist %s", item.Value, list.Name)

		rng, err := csnet.NewRange(item.Value)
		if err != nil {
			c.Log.Error(err)
			continue
		}

		query := txClient.AllowListItem.Create().
			SetValue(item.Value).
			SetIPSize(int64(rng.Size())).
			SetStartIP(rng.Start.Addr).
			SetStartSuffix(rng.Start.Sfx).
			SetEndIP(rng.End.Addr).
			SetEndSuffix(rng.End.Sfx).
			SetComment(item.Description)

		if !time.Time(item.Expiration).IsZero() {
			query = query.SetExpiresAt(time.Time(item.Expiration).UTC())
		}

		content, err := query.Save(ctx)
		if err != nil {
			return 0, rollbackOnError(txClient, err, "unable to add value to allowlist")
		}

		c.Log.Debugf("Updating allowlist %s with value %s (exp: %s)", list.Name, item.Value, item.Expiration)

		// We don't have a clean way to handle name conflict from the console, so use id
		err = txClient.AllowList.Update().AddAllowlistItems(content).Where(allowlist.IDEQ(list.ID)).Exec(ctx)
		if err != nil {
			c.Log.Errorf("unable to add value to allowlist: %s", err)
			continue
		}

		added++
	}

	err = txClient.Commit()
	if err != nil {
		return 0, rollbackOnError(txClient, err, "error committing transaction")
	}

	return added, nil
}

func (c *Client) RemoveFromAllowlist(ctx context.Context, list *ent.AllowList, values ...string) (int, error) {
	c.Log.Debugf("removing %d values from allowlist %s", len(values), list.Name)
	c.Log.Tracef("values: %v", values)

	nbDeleted, err := c.Ent.AllowListItem.Delete().Where(
		allowlistitem.HasAllowlistWith(allowlist.IDEQ(list.ID)),
		allowlistitem.ValueIn(values...),
	).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("unable to remove values from allowlist: %w", err)
	}

	return nbDeleted, nil
}

func (c *Client) UpdateAllowlistMeta(ctx context.Context, allowlistID string, name string, description string) error {
	c.Log.Debugf("updating allowlist %s meta", name)

	err := c.Ent.AllowList.Update().Where(allowlist.AllowlistIDEQ(allowlistID)).SetName(name).SetDescription(description).Exec(ctx)
	if err != nil {
		return fmt.Errorf("unable to update allowlist: %w", err)
	}

	return nil
}

func (c *Client) ReplaceAllowlist(ctx context.Context, list *ent.AllowList, items []*models.AllowlistItem, fromConsole bool) (int, error) {
	c.Log.Debugf("replacing values in allowlist %s", list.Name)
	c.Log.Tracef("items: %+v", items)

	_, err := c.Ent.AllowListItem.Delete().Where(allowlistitem.HasAllowlistWith(allowlist.IDEQ(list.ID))).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("unable to delete allowlist contents: %w", err)
	}

	added, err := c.AddToAllowlist(ctx, list, items)
	if err != nil {
		return 0, fmt.Errorf("unable to add values to allowlist: %w", err)
	}

	if !list.FromConsole && fromConsole {
		c.Log.Infof("marking allowlist %s as managed from console and replacing its content", list.Name)

		err = c.Ent.AllowList.Update().SetFromConsole(fromConsole).Where(allowlist.IDEQ(list.ID)).Exec(ctx)
		if err != nil {
			return 0, fmt.Errorf("unable to update allowlist: %w", err)
		}
	}

	return added, nil
}

func (c *Client) IsAllowlistedBy(ctx context.Context, value string) ([]string, error) {
	/*
		Few cases:
		- value is an IP/range directly is in allowlist
		- value is an IP/range in a range in allowlist
		- value is a range and an IP/range belonging to it is in allowlist
	*/
	rng, err := csnet.NewRange(value)
	if err != nil {
		return nil, err
	}

	c.Log.Debugf("checking if %s is allowlisted", value)

	now := time.Now().UTC()
	query := c.Ent.AllowListItem.Query().Where(
		allowlistitem.Or(
			allowlistitem.ExpiresAtGTE(now),
			allowlistitem.ExpiresAtIsNil(),
		),
		allowlistitem.IPSizeEQ(int64(rng.Size())),
	)

	if rng.Size() == 4 {
		query = query.Where(
			allowlistitem.Or(
				// Value contained inside a range or exact match
				allowlistitem.And(
					allowlistitem.StartIPLTE(rng.Start.Addr),
					allowlistitem.EndIPGTE(rng.End.Addr),
				),
				// Value contains another allowlisted value
				allowlistitem.And(
					allowlistitem.StartIPGTE(rng.Start.Addr),
					allowlistitem.EndIPLTE(rng.End.Addr),
				),
			))
	}

	if rng.Size() == 16 {
		query = query.Where(
			// Value contained inside a range or exact match
			allowlistitem.Or(
				allowlistitem.And(
					allowlistitem.Or(
						allowlistitem.StartIPLT(rng.Start.Addr),
						allowlistitem.And(
							allowlistitem.StartIPEQ(rng.Start.Addr),
							allowlistitem.StartSuffixLTE(rng.Start.Sfx),
						)),
					allowlistitem.Or(
						allowlistitem.EndIPGT(rng.End.Addr),
						allowlistitem.And(
							allowlistitem.EndIPEQ(rng.End.Addr),
							allowlistitem.EndSuffixGTE(rng.End.Sfx),
						),
					),
				),
				// Value contains another allowlisted value
				allowlistitem.And(
					allowlistitem.Or(
						allowlistitem.StartIPGT(rng.Start.Addr),
						allowlistitem.And(
							allowlistitem.StartIPEQ(rng.Start.Addr),
							allowlistitem.StartSuffixGTE(rng.Start.Sfx),
						)),
					allowlistitem.Or(
						allowlistitem.EndIPLT(rng.End.Addr),
						allowlistitem.And(
							allowlistitem.EndIPEQ(rng.End.Addr),
							allowlistitem.EndSuffixLTE(rng.End.Sfx),
						),
					),
				),
			),
		)
	}

	items, err := query.WithAllowlist().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to check if value is allowlisted: %w", err)
	}

	reasons := make([]string, 0)

	for _, item := range items {
		if len(item.Edges.Allowlist) == 0 {
			continue
		}

		reason := item.Value + " from " + item.Edges.Allowlist[0].Name
		if item.Comment != "" {
			reason += " (" + item.Comment + ")"
		}

		reasons = append(reasons, reason)
	}

	return reasons, nil
}

func (c *Client) IsAllowlisted(ctx context.Context, value string) (bool, string, error) {
	reasons, err := c.IsAllowlistedBy(ctx, value)
	if err != nil {
		return false, "", err
	}

	if len(reasons) == 0 {
		return false, "", nil
	}

	reason := strings.Join(reasons, ", ")

	return true, reason, nil
}

func (c *Client) GetAllowlistsContentForAPIC(ctx context.Context) ([]net.IP, []*net.IPNet, error) {
	allowlists, err := c.ListAllowLists(ctx, true)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get allowlists: %w", err)
	}

	var (
		ips  []net.IP
		nets []*net.IPNet
	)

	for _, allowlist := range allowlists {
		for _, item := range allowlist.Edges.AllowlistItems {
			if item.ExpiresAt.IsZero() || item.ExpiresAt.After(time.Now().UTC()) {
				if strings.Contains(item.Value, "/") {
					_, ipNet, err := net.ParseCIDR(item.Value)
					if err != nil {
						c.Log.Errorf("unable to parse CIDR %s: %s", item.Value, err)
						continue
					}

					nets = append(nets, ipNet)
				} else {
					ip := net.ParseIP(item.Value)
					if ip == nil {
						c.Log.Errorf("unable to parse IP %s", item.Value)
						continue
					}

					ips = append(ips, ip)
				}
			}
		}
	}

	return ips, nets, nil
}

func (c *Client) ApplyAllowlistsToExistingDecisions(ctx context.Context) (int, error) {
	// Soft delete (set expiration to now) all decisions that matches any allowlist
	totalCount := 0

	// Get all non-expired allowlist items
	// We will match them one by one against all decisions
	allowlistItems, err := c.Ent.AllowListItem.Query().
		Where(
			allowlistitem.Or(
				allowlistitem.ExpiresAtGTE(time.Now().UTC()),
				allowlistitem.ExpiresAtIsNil(),
			),
		).All(ctx)
	if err != nil {
		return 0, fmt.Errorf("unable to get allowlist items: %w", err)
	}

	now := time.Now().UTC()

	for _, item := range allowlistItems {
		updateQuery := c.Ent.Decision.Update().SetUntil(now).Where(decision.UntilGTE(now))

		switch item.IPSize {
		case 4:
			updateQuery = updateQuery.Where(
				decision.And(
					decision.IPSizeEQ(4),
					decision.Or(
						decision.And(
							decision.StartIPLTE(item.StartIP),
							decision.EndIPGTE(item.EndIP),
						),
						decision.And(
							decision.StartIPGTE(item.StartIP),
							decision.EndIPLTE(item.EndIP),
						),
					)))
		case 16:
			updateQuery = updateQuery.Where(
				decision.And(
					decision.IPSizeEQ(16),
					decision.Or(
						decision.And(
							decision.Or(
								decision.StartIPLT(item.StartIP),
								decision.And(
									decision.StartIPEQ(item.StartIP),
									decision.StartSuffixLTE(item.StartSuffix),
								)),
							decision.Or(
								decision.EndIPGT(item.EndIP),
								decision.And(
									decision.EndIPEQ(item.EndIP),
									decision.EndSuffixGTE(item.EndSuffix),
								),
							),
						),
						decision.And(
							decision.Or(
								decision.StartIPGT(item.StartIP),
								decision.And(
									decision.StartIPEQ(item.StartIP),
									decision.StartSuffixGTE(item.StartSuffix),
								)),
							decision.Or(
								decision.EndIPLT(item.EndIP),
								decision.And(
									decision.EndIPEQ(item.EndIP),
									decision.EndSuffixLTE(item.EndSuffix),
								),
							),
						),
					),
				),
			)
		default:
			// This should never happen
			// But better safe than sorry and just skip it instead of expiring all decisions
			c.Log.Errorf("unexpected IP size %d for allowlist item %s", item.IPSize, item.Value)
			continue
		}
		// Update the decisions
		count, err := updateQuery.Save(ctx)
		if err != nil {
			c.Log.Errorf("unable to expire existing decisions: %s", err)
			continue
		}

		totalCount += count
	}

	return totalCount, nil
}
