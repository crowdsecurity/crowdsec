package apiclient

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	qs "github.com/google/go-querystring/query"
)

// type ApiAlerts service

type AlertsService service

type AlertsListOpts struct {
	Scope_equals *string `url:"scope,omitempty"`
	Value_equals *string `url:"value,omitempty"`
	Type_equals  *string `url:"type,omitempty"`
	ListOpts
}

func (s *AlertsService) Add(ctx context.Context, alerts models.AddAlertsRequest) (*models.AddAlertsResponse, *Response, error) {

	var added_ids models.AddAlertsResponse

	u := "alerts"
	req, err := s.client.NewRequest("POST", u, &alerts)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &added_ids)
	if err != nil {
		return nil, resp, err
	}
	return &added_ids, resp, nil
}

//to demo query arguments
func (s *AlertsService) List(ctx context.Context, opts AlertsListOpts) (*models.GetAlertsResponse, *Response, error) {
	var alerts models.GetAlertsResponse
	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("alerts/?%s", params.Encode())

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &alerts)
	if err != nil {
		return nil, resp, err
	}
	return &alerts, resp, nil
}
