// Code generated by go-swagger; DO NOT EDIT.

package modelscapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// GetDecisionsStreamResponseNewItem New Decisions
//
// swagger:model GetDecisionsStreamResponseNewItem
type GetDecisionsStreamResponseNewItem struct {

	// decisions
	// Required: true
	Decisions []*GetDecisionsStreamResponseNewItemDecisionsItems0 `json:"decisions"`

	// scenario
	// Required: true
	Scenario *string `json:"scenario"`

	// the scope of decision : does it apply to an IP, a range, a username, etc
	// Required: true
	Scope *string `json:"scope"`
}

// Validate validates this get decisions stream response new item
func (m *GetDecisionsStreamResponseNewItem) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDecisions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScenario(formats); err != nil {
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

func (m *GetDecisionsStreamResponseNewItem) validateDecisions(formats strfmt.Registry) error {

	if err := validate.Required("decisions", "body", m.Decisions); err != nil {
		return err
	}

	for i := 0; i < len(m.Decisions); i++ {
		if swag.IsZero(m.Decisions[i]) { // not required
			continue
		}

		if m.Decisions[i] != nil {
			if err := m.Decisions[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("decisions" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("decisions" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GetDecisionsStreamResponseNewItem) validateScenario(formats strfmt.Registry) error {

	if err := validate.Required("scenario", "body", m.Scenario); err != nil {
		return err
	}

	return nil
}

func (m *GetDecisionsStreamResponseNewItem) validateScope(formats strfmt.Registry) error {

	if err := validate.Required("scope", "body", m.Scope); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this get decisions stream response new item based on the context it is used
func (m *GetDecisionsStreamResponseNewItem) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDecisions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetDecisionsStreamResponseNewItem) contextValidateDecisions(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Decisions); i++ {

		if m.Decisions[i] != nil {

			if swag.IsZero(m.Decisions[i]) { // not required
				return nil
			}

			if err := m.Decisions[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("decisions" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("decisions" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *GetDecisionsStreamResponseNewItem) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetDecisionsStreamResponseNewItem) UnmarshalBinary(b []byte) error {
	var res GetDecisionsStreamResponseNewItem
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// GetDecisionsStreamResponseNewItemDecisionsItems0 get decisions stream response new item decisions items0
//
// swagger:model GetDecisionsStreamResponseNewItemDecisionsItems0
type GetDecisionsStreamResponseNewItemDecisionsItems0 struct {

	// duration
	// Required: true
	Duration *string `json:"duration"`

	// the value of the decision scope : an IP, a range, a username, etc
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this get decisions stream response new item decisions items0
func (m *GetDecisionsStreamResponseNewItemDecisionsItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDuration(formats); err != nil {
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

func (m *GetDecisionsStreamResponseNewItemDecisionsItems0) validateDuration(formats strfmt.Registry) error {

	if err := validate.Required("duration", "body", m.Duration); err != nil {
		return err
	}

	return nil
}

func (m *GetDecisionsStreamResponseNewItemDecisionsItems0) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this get decisions stream response new item decisions items0 based on context it is used
func (m *GetDecisionsStreamResponseNewItemDecisionsItems0) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GetDecisionsStreamResponseNewItemDecisionsItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetDecisionsStreamResponseNewItemDecisionsItems0) UnmarshalBinary(b []byte) error {
	var res GetDecisionsStreamResponseNewItemDecisionsItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
