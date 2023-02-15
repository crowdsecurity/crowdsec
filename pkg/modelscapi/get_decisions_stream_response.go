// Code generated by go-swagger; DO NOT EDIT.

package modelscapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GetDecisionsStreamResponse get decisions stream response
//
// get decision response model
//
// swagger:model GetDecisionsStreamResponse
type GetDecisionsStreamResponse struct {

	// deleted
	Deleted GetDecisionsStreamResponseDeleted `json:"deleted,omitempty"`

	// links
	Links *GetDecisionsStreamResponseLinks `json:"links,omitempty"`

	// new
	New GetDecisionsStreamResponseNew `json:"new,omitempty"`
}

// Validate validates this get decisions stream response
func (m *GetDecisionsStreamResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDeleted(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNew(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetDecisionsStreamResponse) validateDeleted(formats strfmt.Registry) error {
	if swag.IsZero(m.Deleted) { // not required
		return nil
	}

	if err := m.Deleted.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("deleted")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("deleted")
		}
		return err
	}

	return nil
}

func (m *GetDecisionsStreamResponse) validateLinks(formats strfmt.Registry) error {
	if swag.IsZero(m.Links) { // not required
		return nil
	}

	if m.Links != nil {
		if err := m.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("links")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("links")
			}
			return err
		}
	}

	return nil
}

func (m *GetDecisionsStreamResponse) validateNew(formats strfmt.Registry) error {
	if swag.IsZero(m.New) { // not required
		return nil
	}

	if err := m.New.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("new")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("new")
		}
		return err
	}

	return nil
}

// ContextValidate validate this get decisions stream response based on the context it is used
func (m *GetDecisionsStreamResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDeleted(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLinks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNew(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetDecisionsStreamResponse) contextValidateDeleted(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Deleted.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("deleted")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("deleted")
		}
		return err
	}

	return nil
}

func (m *GetDecisionsStreamResponse) contextValidateLinks(ctx context.Context, formats strfmt.Registry) error {

	if m.Links != nil {
		if err := m.Links.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("links")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("links")
			}
			return err
		}
	}

	return nil
}

func (m *GetDecisionsStreamResponse) contextValidateNew(ctx context.Context, formats strfmt.Registry) error {

	if err := m.New.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("new")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("new")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GetDecisionsStreamResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetDecisionsStreamResponse) UnmarshalBinary(b []byte) error {
	var res GetDecisionsStreamResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
