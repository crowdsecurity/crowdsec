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

// EnrollRequest enroll request
//
// enroll request model
//
// swagger:model EnrollRequest
type EnrollRequest struct {

	// attachment_key is generated in your crowdsec backoffice account and allows you to enroll your machines to your BO account
	// Required: true
	// Pattern: ^[a-zA-Z0-9]+$
	AttachmentKey *string `json:"attachment_key"`

	// The name that will be display in the console for the instance
	Name string `json:"name,omitempty"`

	// To force enroll the instance
	Overwrite bool `json:"overwrite,omitempty"`

	// Tags to apply on the console for the instance
	Tags []string `json:"tags"`
}

// Validate validates this enroll request
func (m *EnrollRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttachmentKey(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EnrollRequest) validateAttachmentKey(formats strfmt.Registry) error {

	if err := validate.Required("attachment_key", "body", m.AttachmentKey); err != nil {
		return err
	}

	if err := validate.Pattern("attachment_key", "body", *m.AttachmentKey, `^[a-zA-Z0-9]+$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this enroll request based on context it is used
func (m *EnrollRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *EnrollRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EnrollRequest) UnmarshalBinary(b []byte) error {
	var res EnrollRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
