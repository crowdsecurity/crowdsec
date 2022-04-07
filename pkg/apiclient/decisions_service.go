package apiclient

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	qs "github.com/google/go-querystring/query"
)

type DecisionsService service

type DecisionsListOpts struct {
	ScopeEquals *string `url:"scope,omitempty"`
	ValueEquals *string `url:"value,omitempty"`
	TypeEquals  *string `url:"type,omitempty"`
	IPEquals    *string `url:"ip,omitempty"`
	RangeEquals *string `url:"range,omitempty"`
	Contains    *bool   `url:"contains,omitempty"`
	ListOpts
}

type DecisionsStreamOpts struct {
	Startup                bool   `url:"startup,omitempty"`
	Scopes                 string `url:"scopes,omitempty"`
	ScenariosContaining    string `url:"scenarios_containing,omitempty"`
	ScenariosNotContaining string `url:"scenarios_not_containing,omitempty"`
	Origins                string `url:"origins,omitempty"`
}

func (o *DecisionsStreamOpts) addQueryParamsToURL(url string) (string, error) {
	params, err := qs.Values(o)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s?%s", url, params.Encode()), nil
}

type DecisionsDeleteOpts struct {
	ScopeEquals *string `url:"scope,omitempty"`
	ValueEquals *string `url:"value,omitempty"`
	TypeEquals  *string `url:"type,omitempty"`
	IPEquals    *string `url:"ip,omitempty"`
	RangeEquals *string `url:"range,omitempty"`
	Contains    *bool   `url:"contains,omitempty"`
	ListOpts
}

//to demo query arguments
func (s *DecisionsService) List(ctx context.Context, opts DecisionsListOpts) (*models.GetDecisionsResponse, *Response, error) {
	var decisions models.GetDecisionsResponse
	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("%s/decisions?%s", s.client.URLPrefix, params.Encode())

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}
	return &decisions, resp, nil
}

func (s *DecisionsService) GetStream(ctx context.Context, opts DecisionsStreamOpts) (*models.DecisionsStreamResponse, *Response, error) {
	var decisions models.DecisionsStreamResponse
	u, err := opts.addQueryParamsToURL(s.client.URLPrefix + "/decisions/stream")
	if err != nil {
		return nil, nil, err
	}
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	return &decisions, resp, nil
}

func (s *DecisionsService) StopStream(ctx context.Context) (*Response, error) {

	u := fmt.Sprintf("%s/decisions", s.client.URLPrefix)
	req, err := s.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func (s *DecisionsService) Delete(ctx context.Context, opts DecisionsDeleteOpts) (*models.DeleteDecisionResponse, *Response, error) {
	var deleteDecisionResponse models.DeleteDecisionResponse
	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("%s/decisions?%s", s.client.URLPrefix, params.Encode())

	req, err := s.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &deleteDecisionResponse)
	if err != nil {
		return nil, resp, err
	}
	return &deleteDecisionResponse, resp, nil
}

func (s *DecisionsService) DeleteOne(ctx context.Context, decision_id string) (*models.DeleteDecisionResponse, *Response, error) {
	var deleteDecisionResponse models.DeleteDecisionResponse
	u := fmt.Sprintf("%s/decisions/%s", s.client.URLPrefix, decision_id)

	req, err := s.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &deleteDecisionResponse)
	if err != nil {
		return nil, resp, err
	}
	return &deleteDecisionResponse, resp, nil
}
