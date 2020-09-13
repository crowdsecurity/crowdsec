package database

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func (c *Client) CreateMachine(machineID string, password string, ipAddres string) (*ent.Machine, error) {
	machineExist, err := c.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(machineID)).
		Select(machine.FieldMachineId).Strings(c.CTX)
	if len(machineExist) > 0 {
		return &ent.Machine{}, errors.Wrap(UserExists, fmt.Sprintf("user '%s'", machineID))
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return &ent.Machine{}, errors.Wrap(HashError, "")
	}

	machines, err := c.Ent.Machine.
		Create().
		SetMachineId(machineID).
		SetPassword(string(hashPassword)).
		SetIpAddress(ipAddres).
		Save(c.CTX)

	if err != nil {
		return &ent.Machine{}, errors.Wrap(UserExists, fmt.Sprintf("creating machine '%s'", machineID))
	}

	return machines, nil
}

func (c *Client) QueryMachineByID(machineID string) (*ent.Machine, error) {
	machine, err := c.Ent.Debug().Machine.
		Query().
		Where(machine.MachineIdEQ(machineID)).
		Only(c.CTX)
	if err != nil {
		return &ent.Machine{}, errors.Wrap(UserNotExists, fmt.Sprintf("user '%s'", machineID))
	}
	return machine, nil
}

func (c *Client) QueryAllMachines() ([]*ent.Machine, error) {
	var machines []*ent.Machine
	var err error

	machines, err = c.Ent.Machine.Query().All(c.CTX)
	if err != nil {
		return []*ent.Machine{}, errors.Wrap(UpdateFail, "setting machine status")
	}
	return machines, nil
}

func (c *Client) ValidateMachine(machineID string) error {
	_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(machineID)).SetIsValidated(true).Save(c.CTX)
	if err != nil {
		return errors.Wrap(UpdateFail, "setting machine status")
	}
	return nil
}

func (c *Client) QueryPendingMachine() ([]*ent.Machine, error) {
	var machines []*ent.Machine
	var err error

	machines, err = c.Ent.Machine.Query().Where(machine.IsValidatedEQ(false)).All(c.CTX)
	if err != nil {
		return []*ent.Machine{}, errors.Wrap(UpdateFail, "setting machine status")
	}
	return machines, nil
}
