package database

import (
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func (c *Client) CreateMachine(machineID *string, password *strfmt.Password, ipAddress string, isValidated bool, force bool) (int, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		log.Warningf("CreateMachine : %s", err)
		return 0, errors.Wrap(HashError, "")
	}

	machineExist, err := c.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(*machineID)).
		Select(machine.FieldMachineId).Strings(c.CTX)
	if err != nil {
		return 0, errors.Wrapf(QueryFail, "machine '%s': %s", *machineID, err)
	}
	if len(machineExist) > 0 {
		if force {
			_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(*machineID)).SetPassword(string(hashPassword)).Save(c.CTX)
			if err != nil {
				log.Warningf("CreateMachine : %s", err)
				return 0, errors.Wrapf(UpdateFail, "machine '%s'", *machineID)
			}
			return 1, nil
		}
		return 0, errors.Wrapf(UserExists, "user '%s'", *machineID)
	}

	_, err = c.Ent.Machine.
		Create().
		SetMachineId(*machineID).
		SetPassword(string(hashPassword)).
		SetIpAddress(ipAddress).
		SetIsValidated(isValidated).
		Save(c.CTX)

	if err != nil {
		log.Warningf("CreateMachine : %s", err)
		return 0, errors.Wrapf(InsertFail, "creating machine '%s'", *machineID)
	}

	return 1, nil
}

func (c *Client) QueryMachineByID(machineID string) (*ent.Machine, error) {
	machine, err := c.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(machineID)).
		Only(c.CTX)
	if err != nil {
		log.Warningf("QueryMachineByID : %s", err)
		return &ent.Machine{}, errors.Wrapf(UserNotExists, "user '%s'", machineID)
	}
	return machine, nil
}

func (c *Client) ListMachines() ([]*ent.Machine, error) {
	machines, err := c.Ent.Machine.Query().All(c.CTX)
	if err != nil {
		log.Warningf("ListMachines : %s", err)
		return []*ent.Machine{}, errors.Wrap(UpdateFail, "setting machine status")
	}
	return machines, nil
}

func (c *Client) ValidateMachine(machineID string) error {
	_, err := c.Ent.Machine.Update().Where(machine.MachineIdEQ(machineID)).SetIsValidated(true).Save(c.CTX)
	if err != nil {
		log.Warningf("ValidateMachine : %s", err)
		return errors.Wrap(UpdateFail, "setting machine status")
	}
	return nil
}

func (c *Client) QueryPendingMachine() ([]*ent.Machine, error) {
	var machines []*ent.Machine
	var err error

	machines, err = c.Ent.Machine.Query().Where(machine.IsValidatedEQ(false)).All(c.CTX)
	if err != nil {
		log.Warningf("QueryPendingMachine : %s", err)
		return []*ent.Machine{}, errors.Wrap(UpdateFail, "setting machine status")
	}
	return machines, nil
}

func (c *Client) DeleteWatcher(name string) error {
	_, err := c.Ent.Machine.
		Delete().
		Where(machine.MachineIdEQ(name)).
		Exec(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to save api key in database: %s", err)
	}
	return nil
}

func (c *Client) UpdateMachineScenarios(scenarios string, ID int) error {
	_, err := c.Ent.Machine.UpdateOneID(ID).
		SetUpdatedAt(time.Now()).
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
		return fmt.Errorf("unable to update machine in database: %s", err)
	}
	return nil
}

func (c *Client) UpdateMachineVersion(ipAddr string, ID int) error {
	_, err := c.Ent.Machine.UpdateOneID(ID).
		SetVersion(ipAddr).
		Save(c.CTX)
	if err != nil {
		return fmt.Errorf("unable to update machine in database: %s", err)
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
		return false, fmt.Errorf("More than one item with the same machineID in database")
	}

	return false, nil

}
