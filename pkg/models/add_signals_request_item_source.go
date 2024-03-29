// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AddSignalsRequestItemSource Source
//
// swagger:model AddSignalsRequestItemSource
type AddSignalsRequestItemSource struct {

	// provided as a convenience when the source is an IP
	AsName string `json:"as_name,omitempty"`

	// provided as a convenience when the source is an IP
	AsNumber string `json:"as_number,omitempty"`

	// cn
	Cn string `json:"cn,omitempty"`

	// provided as a convenience when the source is an IP
	IP string `json:"ip,omitempty"`

	// latitude
	Latitude float32 `json:"latitude,omitempty"`

	// longitude
	Longitude float32 `json:"longitude,omitempty"`

	// provided as a convenience when the source is an IP
	Range string `json:"range,omitempty"`

	// the scope of a source : ip,range,username,etc
	// Required: true
	Scope *string `json:"scope"`

	// the value of a source : the ip, the range, the username,etc
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this add signals request item source
func (m *AddSignalsRequestItemSource) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateScope(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AddSignalsRequestItemSource) validateScope(formats strfmt.Registry) error {

	if err := validate.Required("scope", "body", m.Scope); err != nil {
		return err
	}

	return nil
}

func (m *AddSignalsRequestItemSource) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this add signals request item source based on context it is used
func (m *AddSignalsRequestItemSource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AddSignalsRequestItemSource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AddSignalsRequestItemSource) UnmarshalBinary(b []byte) error {
	var res AddSignalsRequestItemSource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
