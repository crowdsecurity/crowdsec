package database

import (
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const CapiMachineID = types.CAPIOrigin
const CapiListsMachineID = types.ListOrigin

func (c *Client) CreateMachine(machineID *string, password *strfmt.Password, ipAddress string, isValidated bool, force bool, authType string) (*ent.Machine, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		c.Log.Warningf("CreateMachine: %s", err)
		return nil, HashError
	}

	machineExist, err := c.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(*machineID)).
		Select(machine.FieldMachineId).Strings(c.CTX)
	if err != nil {
		return nil, errors.Wrapf(QueryFail, "machine '%s': %s", *machineID, err)
	}
	if len(machineExist) > 0 {
		if force {
			_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(*machineID)).SetPassword(string(hashPassword)).Save(c.CTX)
			if err != nil {
				c.Log.Warningf("CreateMachine : %s", err)
				return nil, errors.Wrapf(UpdateFail, "machine '%s'", *machineID)
			}
			machine, err := c.QueryMachineByID(*machineID)
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
		Save(c.CTX)

	if err != nil {
		c.Log.Warningf("CreateMachine : %s", err)
		return nil, errors.Wrapf(InsertFail, "creating machine '%s'", *machineID)
	}

	return machine, nil
}

func (c *Client) QueryMachineByID(machineID string) (*ent.Machine, error) {
	machine, err := c.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(machineID)).
		Only(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryMachineByID : %s", err)
		return &ent.Machine{}, errors.Wrapf(UserNotExists, "user '%s'", machineID)
	}
	return machine, nil
}

func (c *Client) ListMachines() ([]*ent.Machine, error) {
	machines, err := c.Ent.Machine.Query().All(c.CTX)
	if err != nil {
		return nil, errors.Wrapf(QueryFail, "listing machines: %s", err)
	}
	return machines, nil
}

func (c *Client) ValidateMachine(machineID string) error {
	rets, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(machineID)).SetIsValidated(true).Save(c.CTX)
	if err != nil {
		return errors.Wrapf(UpdateFail, "validating machine: %s", err)
	}
	if rets == 0 {
		return fmt.Errorf("machine not found")
	}
	return nil
}

func (c *Client) QueryPendingMachine() ([]*ent.Machine, error) {
	var machines []*ent.Machine
	var err error

	machines, err = c.Ent.Machine.Query().Where(machine.IsValidatedEQ(false)).All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryPendingMachine : %s", err)
		return nil, errors.Wrapf(QueryFail, "querying pending machines: %s", err)
	}
	return machines, nil
}

func (c *Client) DeleteWatcher(name string) error {
	nbDeleted, err := c.Ent.Machine.
		Delete().
		Where(machine.MachineIdEQ(name)).
		Exec(c.CTX)
	if err != nil {
		return err
	}

	if nbDeleted == 0 {
		return fmt.Errorf("machine doesn't exist")
	}

	return nil
}

func (c *Client) BulkDeleteWatchers(machines []*ent.Machine) (int, error) {
	ids := make([]int, len(machines))
	for i, b := range machines {
		ids[i] = b.ID
	}
	nbDeleted, err := c.Ent.Machine.Delete().Where(machine.IDIn(ids...)).Exec(c.CTX)
	if err != nil {
		return nbDeleted, err
	}
	return nbDeleted, nil
}

func (c *Client) UpdateMachineLastPush(machineID string) error {
	_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(machineID)).SetLastPush(time.Now().UTC()).Save(c.CTX)
	if err != nil {
		return errors.Wrapf(UpdateFail, "updating machine last_push: %s", err)
	}
	return nil
}

func (c *Client) UpdateMachineLastHeartBeat(machineID string) error {
	_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(machineID)).SetLastHeartbeat(time.Now().UTC()).Save(c.CTX)
	if err != nil {
		return errors.Wrapf(UpdateFail, "updating machine last_heartbeat: %s", err)
	}
	return nil
}

func (c *Client) UpdateMachineScenarios(scenarios string, ID int) error {
	_, err := c.Ent.Machine.UpdateOneID(ID).
		SetUpdatedAt(time.Now().UTC()).
		SetScenarios(scenarios).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update machine in database: %s", err)
	}
	return nil
}

func (c *Client) UpdateMachineIP(ipAddr string, ID int) error {
	_, err := c.Ent.Machine.UpdateOneID(ID).
		SetIpAddress(ipAddr).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update machine IP in database: %s", err)
	}
	return nil
}

func (c *Client) UpdateMachineVersion(ipAddr string, ID int) error {
	_, err := c.Ent.Machine.UpdateOneID(ID).
		SetVersion(ipAddr).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update machine version in database: %s", err)
	}
	return nil
}

func (c *Client) IsMachineRegistered(machineID string) (bool, error) {
	exist, err := c.Ent.Machine.Query().Where().Select(machine.FieldMachineId).Strings(c.CTX)
	if err != nil {
		return false, err
	}
	if len(exist) == 1 {
		return true, nil
	}
	if len(exist) > 1 {
		return false, fmt.Errorf("more than one item with the same machineID in database")
	}

	return false, nil

}

func (c *Client) QueryLastValidatedHeartbeatLT(t time.Time) ([]*ent.Machine, error) {
	return c.Ent.Machine.Query().Where(machine.LastHeartbeatLT(t), machine.IsValidatedEQ(true)).All(c.CTX)
}
