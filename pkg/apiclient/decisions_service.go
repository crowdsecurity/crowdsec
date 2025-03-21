package apiclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"

	qs "github.com/google/go-querystring/query"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
	CommunityPull          bool   `url:"community_pull"`
	AdditionalPull         bool   `url:"additional_pull"`
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

	// Those 2 are a bit different
	// They default to true, and we only want to include them if they are false

	if params.Get("community_pull") == "true" {
		params.Del("community_pull")
	}

	if params.Get("additional_pull") == "true" {
		params.Del("additional_pull")
	}

	return fmt.Sprintf("%s?%s", url, params.Encode()), nil
}

type DecisionsDeleteOpts struct {
	ScopeEquals  *string `url:"scope,omitempty"`
	ValueEquals  *string `url:"value,omitempty"`
	TypeEquals   *string `url:"type,omitempty"`
	IPEquals     *string `url:"ip,omitempty"`
	RangeEquals  *string `url:"range,omitempty"`
	Contains     *bool   `url:"contains,omitempty"`
	OriginEquals *string `url:"origin,omitempty"`
	//
	ScenarioEquals *string `url:"scenario,omitempty"`
	ListOpts
}

// to demo query arguments
func (s *DecisionsService) List(ctx context.Context, opts DecisionsListOpts) (*models.GetDecisionsResponse, *Response, error) {
	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, err
	}

	u := fmt.Sprintf("%s/decisions?%s", s.client.URLPrefix, params.Encode())

	req, err := s.client.PrepareRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}

	var decisions models.GetDecisionsResponse

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	return &decisions, resp, nil
}

func (s *DecisionsService) FetchV2Decisions(ctx context.Context, url string) (*models.DecisionsStreamResponse, *Response, error) {
	req, err := s.client.PrepareRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	var decisions models.DecisionsStreamResponse

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	return &decisions, resp, nil
}

func (s *DecisionsService) GetDecisionsFromGroups(decisionsGroups []*modelscapi.GetDecisionsStreamResponseNewItem) []*models.Decision {
	decisions := make([]*models.Decision, 0)

	for _, decisionsGroup := range decisionsGroups {
		partialDecisions := make([]*models.Decision, len(decisionsGroup.Decisions))
		for idx, decision := range decisionsGroup.Decisions {
			partialDecisions[idx] = &models.Decision{
				Scenario: decisionsGroup.Scenario,
				Scope:    decisionsGroup.Scope,
				Type:     ptr.Of(types.DecisionTypeBan),
				Value:    decision.Value,
				Duration: decision.Duration,
				Origin:   ptr.Of(types.CAPIOrigin),
			}
		}

		decisions = append(decisions, partialDecisions...)
	}

	return decisions
}

func (s *DecisionsService) FetchV3Decisions(ctx context.Context, url string) (*models.DecisionsStreamResponse, *Response, error) {
	scenarioDeleted := "deleted"
	durationDeleted := "1h"

	req, err := s.client.PrepareRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	decisions := modelscapi.GetDecisionsStreamResponse{}

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	v2Decisions := models.DecisionsStreamResponse{}
	v2Decisions.New = s.GetDecisionsFromGroups(decisions.New)

	for _, decisionsGroup := range decisions.Deleted {
		partialDecisions := make([]*models.Decision, len(decisionsGroup.Decisions))

		for idx, decision := range decisionsGroup.Decisions {
			decision := decision //nolint:copyloopvar // fix exportloopref linter message
			partialDecisions[idx] = &models.Decision{
				Scenario: &scenarioDeleted,
				Scope:    decisionsGroup.Scope,
				Type:     ptr.Of(types.DecisionTypeBan),
				Value:    &decision,
				Duration: &durationDeleted,
				Origin:   ptr.Of(types.CAPIOrigin),
			}
		}

		v2Decisions.Deleted = append(v2Decisions.Deleted, partialDecisions...)
	}

	return &v2Decisions, resp, nil
}

func (s *DecisionsService) GetDecisionsFromBlocklist(ctx context.Context, blocklist *modelscapi.BlocklistLink, lastPullTimestamp *string) ([]*models.Decision, bool, error) {
	if blocklist.URL == nil {
		return nil, false, errors.New("blocklist URL is nil")
	}

	log.Debugf("Fetching blocklist %s", *blocklist.URL)

	client := http.Client{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *blocklist.URL, http.NoBody)
	if err != nil {
		return nil, false, err
	}

	if lastPullTimestamp != nil {
		req.Header.Set("If-Modified-Since", *lastPullTimestamp)
	}

	log.Debugf("[URL] %s %s", req.Method, req.URL)

	// we don't use client_http Do method because we need the reader and is not provided.
	// We would be forced to use Pipe and goroutine, etc
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		// If we got an error, and the context has been canceled,
		// the context's error is probably more useful.
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		default:
		}

		// If the error type is *url.Error, sanitize its URL before returning.
		log.Errorf("Error fetching blocklist %s: %s", *blocklist.URL, err)

		return nil, false, err
	}

	if resp.StatusCode == http.StatusNotModified {
		if lastPullTimestamp != nil {
			log.Debugf("Blocklist %s has not been modified since %s", *blocklist.URL, *lastPullTimestamp)
		} else {
			log.Debugf("Blocklist %s has not been modified (decisions about to expire)", *blocklist.URL)
		}

		return nil, false, nil
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("Received nok status code %d for blocklist %s", resp.StatusCode, *blocklist.URL)

		return nil, false, nil
	}

	decisions := make([]*models.Decision, 0)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		decision := scanner.Text()
		decisions = append(decisions, &models.Decision{
			Scenario: blocklist.Name,
			Scope:    blocklist.Scope,
			Type:     blocklist.Remediation,
			Value:    &decision,
			Duration: blocklist.Duration,
			Origin:   ptr.Of(types.ListOrigin),
		})
	}

	// here the upper go routine is finished because scanner.Scan() is blocking until pw.Close() is called
	// so it's safe to use the isModified variable here
	return decisions, true, nil
}

func (s *DecisionsService) GetStream(ctx context.Context, opts DecisionsStreamOpts) (*models.DecisionsStreamResponse, *Response, error) {
	u, err := opts.addQueryParamsToURL(s.client.URLPrefix + "/decisions/stream")
	if err != nil {
		return nil, nil, err
	}

	if s.client.URLPrefix != "v3" {
		return s.FetchV2Decisions(ctx, u)
	}

	return s.FetchV3Decisions(ctx, u)
}

func (s *DecisionsService) GetStreamV3(ctx context.Context, opts DecisionsStreamOpts) (*modelscapi.GetDecisionsStreamResponse, *Response, error) {
	u, err := opts.addQueryParamsToURL(s.client.URLPrefix + "/decisions/stream")
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.PrepareRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}

	decisions := modelscapi.GetDecisionsStreamResponse{}

	resp, err := s.client.Do(ctx, req, &decisions)
	if err != nil {
		return nil, resp, err
	}

	return &decisions, resp, nil
}

func (s *DecisionsService) StopStream(ctx context.Context) (*Response, error) {
	u := fmt.Sprintf("%s/decisions", s.client.URLPrefix)

	req, err := s.client.PrepareRequest(ctx, http.MethodDelete, u, nil)
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
	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, err
	}

	u := fmt.Sprintf("%s/decisions?%s", s.client.URLPrefix, params.Encode())

	req, err := s.client.PrepareRequest(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return nil, nil, err
	}

	deleteDecisionResponse := models.DeleteDecisionResponse{}

	resp, err := s.client.Do(ctx, req, &deleteDecisionResponse)
	if err != nil {
		return nil, resp, err
	}

	return &deleteDecisionResponse, resp, nil
}

func (s *DecisionsService) DeleteOne(ctx context.Context, decisionID string) (*models.DeleteDecisionResponse, *Response, error) {
	u := fmt.Sprintf("%s/decisions/%s", s.client.URLPrefix, decisionID)

	req, err := s.client.PrepareRequest(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return nil, nil, err
	}

	deleteDecisionResponse := models.DeleteDecisionResponse{}

	resp, err := s.client.Do(ctx, req, &deleteDecisionResponse)
	if err != nil {
		return nil, resp, err
	}

	return &deleteDecisionResponse, resp, nil
}
