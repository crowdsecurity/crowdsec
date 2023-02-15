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

// AddSignalsRequestItemDecisionsItem Decision
//
// swagger:model AddSignalsRequestItemDecisionsItem
type AddSignalsRequestItemDecisionsItem struct {

	// duration
	// Required: true
	Duration *string `json:"duration"`

	// (only relevant for GET ops) the unique id
	// Required: true
	ID *int64 `json:"id"`

	// the origin of the decision : cscli, crowdsec
	// Required: true
	Origin *string `json:"origin"`

	// scenario
	// Required: true
	Scenario *string `json:"scenario"`

	// the scope of decision : does it apply to an IP, a range, a username, etc
	// Required: true
	Scope *string `json:"scope"`

	// simulated
	Simulated bool `json:"simulated,omitempty"`

	// the type of decision, might be 'ban', 'captcha' or something custom. Ignored when watcher (cscli/crowdsec) is pushing to APIL.
	// Required: true
	Type *string `json:"type"`

	// until
	Until string `json:"until,omitempty"`

	// only relevant for LAPI->CAPI, ignored for cscli->LAPI and crowdsec->LAPI
	// Read Only: true
	UUID string `json:"uuid,omitempty"`

	// the value of the decision scope : an IP, a range, a username, etc
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this add signals request item decisions item
func (m *AddSignalsRequestItemDecisionsItem) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrigin(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScenario(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScope(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
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

func (m *AddSignalsRequestItemDecisionsItem) validateDuration(formats strfmt.Registry) error {

	if err := validate.Required("duration", "body", m.Duration); err != nil {
		return err
	}

	return nil
}

func (m *AddSignalsRequestItemDecisionsItem) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *AddSignalsRequestItemDecisionsItem) validateOrigin(formats strfmt.Registry) error {

	if err := validate.Required("origin", "body", m.Origin); err != nil {
		return err
	}

	return nil
}

func (m *AddSignalsRequestItemDecisionsItem) validateScenario(formats strfmt.Registry) error {

	if err := validate.Required("scenario", "body", m.Scenario); err != nil {
		return err
	}

	return nil
}

func (m *AddSignalsRequestItemDecisionsItem) validateScope(formats strfmt.Registry) error {

	if err := validate.Required("scope", "body", m.Scope); err != nil {
		return err
	}

	return nil
}

func (m *AddSignalsRequestItemDecisionsItem) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *AddSignalsRequestItemDecisionsItem) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this add signals request item decisions item based on the context it is used
func (m *AddSignalsRequestItemDecisionsItem) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateUUID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AddSignalsRequestItemDecisionsItem) contextValidateUUID(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "uuid", "body", string(m.UUID)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AddSignalsRequestItemDecisionsItem) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AddSignalsRequestItemDecisionsItem) UnmarshalBinary(b []byte) error {
	var res AddSignalsRequestItemDecisionsItem
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
