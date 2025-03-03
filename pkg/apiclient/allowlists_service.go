package apiclient

import (
	"context"
	"fmt"
	"net/http"

	qs "github.com/google/go-querystring/query"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type AllowlistsService service

type AllowlistListOpts struct {
	WithContent bool `url:"with_content,omitempty"`
}

func (s *AllowlistsService) List(ctx context.Context, opts AllowlistListOpts) (*models.GetAllowlistsResponse, *Response, error) {
	u := s.client.URLPrefix + "/allowlists"

	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("building query: %w", err)
	}

	u += "?" + params.Encode()

	req, err := s.client.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}

	allowlists := &models.GetAllowlistsResponse{}

	resp, err := s.client.Do(ctx, req, allowlists)
	if err != nil {
		return nil, resp, err
	}

	return allowlists, resp, nil
}

type AllowlistGetOpts struct {
	WithContent bool `url:"with_content,omitempty"`
}

func (s *AllowlistsService) Get(ctx context.Context, name string, opts AllowlistGetOpts) (*models.GetAllowlistResponse, *Response, error) {
	u := s.client.URLPrefix + "/allowlists/" + name

	params, err := qs.Values(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("building query: %w", err)
	}

	u += "?" + params.Encode()

	log.Debugf("GET %s", u)

	req, err := s.client.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}

	allowlist := &models.GetAllowlistResponse{}

	resp, err := s.client.Do(ctx, req, allowlist)
	if err != nil {
		return nil, resp, err
	}

	return allowlist, resp, nil
}

func (s *AllowlistsService) CheckIfAllowlisted(ctx context.Context, value string) (bool, *Response, error) {
	u := s.client.URLPrefix + "/allowlists/check/" + value

	req, err := s.client.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return false, nil, err
	}

	var discardBody interface{}

	resp, err := s.client.Do(ctx, req, discardBody)
	if err != nil {
		return false, resp, err
	}

	return resp.Response.StatusCode == http.StatusOK, resp, nil
}

func (s *AllowlistsService) CheckIfAllowlistedWithReason(ctx context.Context, value string) (*models.CheckAllowlistResponse, *Response, error) {
	u := s.client.URLPrefix + "/allowlists/check/" + value

	req, err := s.client.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}

	body := &models.CheckAllowlistResponse{}

	resp, err := s.client.Do(ctx, req, body)
	if err != nil {
		return nil, resp, err
	}

	return body, resp, nil
}
