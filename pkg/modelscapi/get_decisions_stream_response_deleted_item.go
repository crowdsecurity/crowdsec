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

// GetDecisionsStreamResponseDeletedItem get decisions stream response deleted item
//
// swagger:model GetDecisionsStreamResponseDeletedItem
type GetDecisionsStreamResponseDeletedItem struct {

	// decisions
	// Required: true
	Decisions []string `json:"decisions"`

	// the scope of decision : does it apply to an IP, a range, a username, etc
	// Required: true
	Scope *string `json:"scope"`
}

// Validate validates this get decisions stream response deleted item
func (m *GetDecisionsStreamResponseDeletedItem) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDecisions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScope(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetDecisionsStreamResponseDeletedItem) validateDecisions(formats strfmt.Registry) error {

	if err := validate.Required("decisions", "body", m.Decisions); err != nil {
		return err
	}

	return nil
}

func (m *GetDecisionsStreamResponseDeletedItem) validateScope(formats strfmt.Registry) error {

	if err := validate.Required("scope", "body", m.Scope); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this get decisions stream response deleted item based on context it is used
func (m *GetDecisionsStreamResponseDeletedItem) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GetDecisionsStreamResponseDeletedItem) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetDecisionsStreamResponseDeletedItem) UnmarshalBinary(b []byte) error {
	var res GetDecisionsStreamResponseDeletedItem
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
