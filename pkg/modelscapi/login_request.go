// Code generated by go-swagger; DO NOT EDIT.

package modelscapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// LoginRequest login request
//
// # Login request model
//
// swagger:model LoginRequest
type LoginRequest struct {

	// machine_id is a (username) generated by crowdsec
	// Required: true
	// Max Length: 48
	// Min Length: 48
	// Pattern: ^[a-zA-Z0-9]+$
	MachineID *string `json:"machine_id"`

	// Password, should respect the password policy (link to add)
	// Required: true
	Password *string `json:"password"`

	// all scenarios installed
	Scenarios []string `json:"scenarios"`
}

// Validate validates this login request
func (m *LoginRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMachineID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePassword(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *LoginRequest) validateMachineID(formats strfmt.Registry) error {

	if err := validate.Required("machine_id", "body", m.MachineID); err != nil {
		return err
	}

	if err := validate.MinLength("machine_id", "body", *m.MachineID, 48); err != nil {
		return err
	}

	if err := validate.MaxLength("machine_id", "body", *m.MachineID, 48); err != nil {
		return err
	}

	if err := validate.Pattern("machine_id", "body", *m.MachineID, `^[a-zA-Z0-9]+$`); err != nil {
		return err
	}

	return nil
}

func (m *LoginRequest) validatePassword(formats strfmt.Registry) error {

	if err := validate.Required("password", "body", m.Password); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this login request based on context it is used
func (m *LoginRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LoginRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginRequest) UnmarshalBinary(b []byte) error {
	var res LoginRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
