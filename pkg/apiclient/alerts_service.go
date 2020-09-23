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
	ScopeEquals          *string `url:"scope,omitempty"`
	ValueEquals          *string `url:"value,omitempty"`
	TypeEquals           *string `url:"type,omitempty"`
	ScenarioEquals       *string `url:"scenario,omitempty"`
	IPEquals             *string `url:"ip,omitempty"`
	RangeEquals          *string `url:"range,omitempty"`
	SinceEquals          *string `url:"since,omitempty"`
	UntilEquals          *string `url:"until,omitempty"`
	ActiveDecisionEquals *bool   `url:"has_active_decision,omitempty"`
	SourceEquals         *string `url:"alert_source,omitempty"`
	ListOpts
}

type AlertsDeleteOpts struct {
	ScopeEquals          *string `url:"scope,omitempty"`
	ValueEquals          *string `url:"value,omitempty"`
	TypeEquals           *string `url:"type,omitempty"`
	ScenarioEquals       *string `url:"scenario,omitempty"`
	IPEquals             *string `url:"ip,omitempty"`
	RangeEquals          *string `url:"range,omitempty"`
	SinceEquals          *string `url:"since,omitempty"`
	UntilEquals          *string `url:"until,omitempty"`
	ActiveDecisionEquals *bool   `url:"has_active_decision,omitempty"`
	SourceEquals         *string `url:"alert_source,omitempty"`
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

//to demo query arguments
func (s *AlertsService) Delete(ctx context.Context, opts AlertsDeleteOpts) (*models.DeleteAlertsResponse, *Response, error) {
	var alerts models.DeleteAlertsResponse
	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("alerts/?%s", params.Encode())

	req, err := s.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &alerts)
	if err != nil {
		return nil, resp, err
	}
	return &alerts, resp, nil
}
