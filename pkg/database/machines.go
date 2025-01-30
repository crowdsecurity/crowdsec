package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/schema"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	CapiMachineID      = types.CAPIOrigin
	CapiListsMachineID = types.ListOrigin
)

type MachineNotFoundError struct {
	MachineID string
}

func (e *MachineNotFoundError) Error() string {
	return fmt.Sprintf("'%s' does not exist", e.MachineID)
}

func (c *Client) MachineUpdateBaseMetrics(ctx context.Context, machineID string, baseMetrics models.BaseMetrics, hubItems models.HubItems, datasources map[string]int64) error {
	os := baseMetrics.Os
	features := strings.Join(baseMetrics.FeatureFlags, ",")

	hubState := map[string][]schema.ItemState{}
	for itemType, items := range hubItems {
		hubState[itemType] = []schema.ItemState{}
		for _, item := range items {
			hubState[itemType] = append(hubState[itemType], schema.ItemState{
				Name:    item.Name,
				Status:  item.Status,
				Version: item.Version,
			})
		}
	}

	_, err := c.Ent.Machine.
		Update().
		Where(machine.MachineIdEQ(machineID)).
		SetNillableVersion(baseMetrics.Version).
		SetOsname(*os.Name).
		SetOsversion(*os.Version).
		SetFeatureflags(features).
		SetHubstate(hubState).
		SetDatasources(datasources).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update base machine metrics in database: %w", err)
	}

	return nil
}

func (c *Client) CreateMachine(ctx context.Context, machineID *string, password *strfmt.Password, ipAddress string, isValidated bool, force bool, authType string) (*ent.Machine, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		c.Log.Warningf("CreateMachine: %s", err)
		return nil, HashError
	}

	machineExist, err := c.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(*machineID)).
		Select(machine.FieldMachineId).Strings(ctx)
	if err != nil {
		return nil, errors.Wrapf(QueryFail, "machine '%s': %s", *machineID, err)
	}

	if len(machineExist) > 0 {
		if force {
			_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(*machineID)).SetPassword(string(hashPassword)).Save(ctx)
			if err != nil {
				c.Log.Warningf("CreateMachine : %s", err)
				return nil, errors.Wrapf(UpdateFail, "machine '%s'", *machineID)
			}

			machine, err := c.QueryMachineByID(ctx, *machineID)
			if err != nil {
				return nil, errors.Wrapf(QueryFail, "machine '%s': %s", *machineID, err)
			}

			return machine, nil
		}

		return nil, errors.Wrapf(UserExists, "user '%s'", *machineID)
	}

	machine, err := c.Ent.Machine.
		Create().
		SetMachineId(*machineID).
		SetPassword(string(hashPassword)).
		SetIpAddress(ipAddress).
		SetIsValidated(isValidated).
		SetAuthType(authType).
		Save(ctx)
	if err != nil {
		c.Log.Warningf("CreateMachine : %s", err)
		return nil, errors.Wrapf(InsertFail, "creating machine '%s'", *machineID)
	}

	return machine, nil
}

func (c *Client) QueryMachineByID(ctx context.Context, machineID string) (*ent.Machine, error) {
	machine, err := c.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(machineID)).
		Only(ctx)
	if err != nil {
		c.Log.Warningf("QueryMachineByID : %s", err)
		return &ent.Machine{}, errors.Wrapf(UserNotExists, "user '%s'", machineID)
	}

	return machine, nil
}

func (c *Client) ListMachines(ctx context.Context) ([]*ent.Machine, error) {
	machines, err := c.Ent.Machine.Query().All(ctx)
	if err != nil {
		return nil, errors.Wrapf(QueryFail, "listing machines: %s", err)
	}

	return machines, nil
}

func (c *Client) ValidateMachine(ctx context.Context, machineID string) error {
	rets, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(machineID)).SetIsValidated(true).Save(ctx)
	if err != nil {
		return errors.Wrapf(UpdateFail, "validating machine: %s", err)
	}

	if rets == 0 {
		return errors.New("machine not found")
	}

	return nil
}

func (c *Client) QueryPendingMachine(ctx context.Context) ([]*ent.Machine, error) {
	machines, err := c.Ent.Machine.Query().Where(machine.IsValidatedEQ(false)).All(ctx)
	if err != nil {
		c.Log.Warningf("QueryPendingMachine : %s", err)
		return nil, errors.Wrapf(QueryFail, "querying pending machines: %s", err)
	}

	return machines, nil
}

func (c *Client) DeleteWatcher(ctx context.Context, name string) error {
	nbDeleted, err := c.Ent.Machine.
		Delete().
		Where(machine.MachineIdEQ(name)).
		Exec(ctx)
	if err != nil {
		return err
	}

	if nbDeleted == 0 {
		return &MachineNotFoundError{MachineID: name}
	}

	return nil
}

func (c *Client) BulkDeleteWatchers(ctx context.Context, machines []*ent.Machine) (int, error) {
	ids := make([]int, len(machines))
	for i, b := range machines {
		ids[i] = b.ID
	}

	nbDeleted, err := c.Ent.Machine.Delete().Where(machine.IDIn(ids...)).Exec(ctx)
	if err != nil {
		return nbDeleted, err
	}

	return nbDeleted, nil
}

func (c *Client) UpdateMachineLastHeartBeat(ctx context.Context, machineID string) error {
	_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(machineID)).SetLastHeartbeat(time.Now().UTC()).Save(ctx)
	if err != nil {
		return errors.Wrapf(UpdateFail, "updating machine last_heartbeat: %s", err)
	}

	return nil
}

func (c *Client) UpdateMachineScenarios(ctx context.Context, scenarios string, id int) error {
	_, err := c.Ent.Machine.UpdateOneID(id).
		SetUpdatedAt(time.Now().UTC()).
		SetScenarios(scenarios).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update machine in database: %w", err)
	}

	return nil
}

func (c *Client) UpdateMachineIP(ctx context.Context, ipAddr string, id int) error {
	_, err := c.Ent.Machine.UpdateOneID(id).
		SetIpAddress(ipAddr).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update machine IP in database: %w", err)
	}

	return nil
}

func (c *Client) UpdateMachineVersion(ctx context.Context, ipAddr string, id int) error {
	_, err := c.Ent.Machine.UpdateOneID(id).
		SetVersion(ipAddr).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to update machine version in database: %w", err)
	}

	return nil
}

func (c *Client) IsMachineRegistered(ctx context.Context, machineID string) (bool, error) {
	exist, err := c.Ent.Machine.Query().Where().Select(machine.FieldMachineId).Strings(ctx)
	if err != nil {
		return false, err
	}

	if len(exist) == 1 {
		return true, nil
	}

	if len(exist) > 1 {
		return false, errors.New("more than one item with the same machineID in database")
	}

	return false, nil
}

func (c *Client) QueryMachinesInactiveSince(ctx context.Context, t time.Time) ([]*ent.Machine, error) {
	return c.Ent.Machine.Query().Where(
		machine.Or(
			machine.And(machine.LastHeartbeatLT(t), machine.IsValidatedEQ(true)),
			machine.And(machine.LastHeartbeatIsNil(), machine.CreatedAtLT(t)),
		),
	).All(ctx)
}
