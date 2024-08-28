package climachine

// Custom types for flag validation and conversion.

import (
	"errors"
)

type MachinePassword string

func (p *MachinePassword) String() string {
	return string(*p)
}

func (p *MachinePassword) Set(v string) error {
	// a password can't be more than 72 characters
	// due to bcrypt limitations
	if len(v) > 72 {
		return errors.New("password too long (max 72 characters)")
	}

	*p = MachinePassword(v)

	return nil
}

func (p *MachinePassword) Type() string {
	return "string"
}
