package apiclient

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	qs "github.com/google/go-querystring/query"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
	//
	ScenarioEquals *string `url:"scenario,omitempty"`
	ListOpts
}

// to demo query arguments
func (s *DecisionsService) List(ctx context.Context, opts DecisionsListOpts) (*models.GetDecisionsResponse, *Response, error) {
	var decisions models.GetDecisionsResponse
	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("%s/decisions?%s", s.client.URLPrefix, params.Encode())

	req, err := s.client.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	return &decisions, resp, nil
}

func (s *DecisionsService) FetchV2Decisions(ctx context.Context, url string) (*models.DecisionsStreamResponse, *Response, error) {
	var decisions models.DecisionsStreamResponse

	req, err := s.client.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	return &decisions, resp, nil
}

func (s *DecisionsService) GetDecisionsFromGroups(decisionsGroups []*modelscapi.GetDecisionsStreamResponseNewItem) []*models.Decision {
	var decisions []*models.Decision

	for _, decisionsGroup := range decisionsGroups {
		partialDecisions := make([]*models.Decision, len(decisionsGroup.Decisions))
		for idx, decision := range decisionsGroup.Decisions {
			partialDecisions[idx] = &models.Decision{
				Scenario: decisionsGroup.Scenario,
				Scope:    decisionsGroup.Scope,
				Type:     types.StrPtr(types.DecisionTypeBan),
				Value:    decision.Value,
				Duration: decision.Duration,
				Origin:   types.StrPtr(types.CAPIOrigin),
			}
		}
		decisions = append(decisions, partialDecisions...)
	}
	return decisions
}

func (s *DecisionsService) FetchV3Decisions(ctx context.Context, url string) (*models.DecisionsStreamResponse, *Response, error) {
	var decisions modelscapi.GetDecisionsStreamResponse
	var v2Decisions models.DecisionsStreamResponse

	scenarioDeleted := "deleted"
	durationDeleted := "1h"

	req, err := s.client.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	v2Decisions.New = s.GetDecisionsFromGroups(decisions.New)
	for _, decisionsGroup := range decisions.Deleted {
		partialDecisions := make([]*models.Decision, len(decisionsGroup.Decisions))
		for idx, decision := range decisionsGroup.Decisions {
			decision := decision // fix exportloopref linter message
			partialDecisions[idx] = &models.Decision{
				Scenario: &scenarioDeleted,
				Scope:    decisionsGroup.Scope,
				Type:     types.StrPtr(types.DecisionTypeBan),
				Value:    &decision,
				Duration: &durationDeleted,
				Origin:   types.StrPtr(types.CAPIOrigin),
			}
		}
		v2Decisions.Deleted = append(v2Decisions.Deleted, partialDecisions...)
	}

	return &v2Decisions, resp, nil
}

func (s *DecisionsService) GetDecisionsFromBlocklist(ctx context.Context, blocklist *modelscapi.BlocklistLink) ([]*models.Decision, error) {
	if blocklist.URL == nil {
		return nil, errors.New("blocklist URL is nil")
	}

	log.Debugf("Fetching blocklist %s", *blocklist.URL)

	req, err := s.client.NewRequest(http.MethodGet, *blocklist.URL, nil)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	defer pr.Close()
	go func() {
		defer pw.Close()
		_, err = s.client.Do(ctx, req, pw)
		if err != nil {
			log.Errorf("Error fetching blocklist %s: %s", *blocklist.URL, err)
		}
	}()
	decisions := make([]*models.Decision, 0)
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		decision := scanner.Text()
		decisions = append(decisions, &models.Decision{
			Scenario: blocklist.Name,
			Scope:    blocklist.Scope,
			Type:     blocklist.Remediation,
			Value:    &decision,
			Duration: blocklist.Duration,
			Origin:   types.StrPtr(types.ListOrigin),
		})
	}

	return decisions, nil
}

func (s *DecisionsService) GetStream(ctx context.Context, opts DecisionsStreamOpts) (*models.DecisionsStreamResponse, *Response, error) {
	u, err := opts.addQueryParamsToURL(s.client.URLPrefix + "/decisions/stream")
	if err != nil {
		return nil, nil, err
	}
	if s.client.URLPrefix == "v3" {
		return s.FetchV3Decisions(ctx, u)
	} else {
		return s.FetchV2Decisions(ctx, u)
	}
}

func (s *DecisionsService) GetStreamV3(ctx context.Context, opts DecisionsStreamOpts) (*modelscapi.GetDecisionsStreamResponse, *Response, error) {
	u, err := opts.addQueryParamsToURL(s.client.URLPrefix + "/decisions/stream")
	if err != nil {
		return nil, nil, err
	}
	var decisions modelscapi.GetDecisionsStreamResponse

	req, err := s.client.NewRequest(http.MethodGet, u, nil)
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
	req, err := s.client.NewRequest(http.MethodDelete, u, nil)
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

	req, err := s.client.NewRequest(http.MethodDelete, u, nil)
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

	req, err := s.client.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &deleteDecisionResponse)
	if err != nil {
		return nil, resp, err
	}
	return &deleteDecisionResponse, resp, nil
}
