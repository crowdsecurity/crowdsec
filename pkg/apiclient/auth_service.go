package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type AuthService service

// Don't add it to the models, as they are used with LAPI, but the enroll endpoint is specific to CAPI
type enrollRequest struct {
	EnrollKey string   `json:"attachment_key"`
	Name      string   `json:"name"`
	Tags      []string `json:"tags"`
	Overwrite bool     `json:"overwrite"`
}

func (s *AuthService) UnregisterWatcher(ctx context.Context) (*Response, error) {
	u := fmt.Sprintf("%s/watchers/self", s.client.URLPrefix)

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

func (s *AuthService) RegisterWatcher(ctx context.Context, registration models.WatcherRegistrationRequest) (*Response, error) {
	u := fmt.Sprintf("%s/watchers", s.client.URLPrefix)

	req, err := s.client.PrepareRequest(ctx, http.MethodPost, u, &registration)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (s *AuthService) AuthenticateWatcher(ctx context.Context, auth models.WatcherAuthRequest) (models.WatcherAuthResponse, *Response, error) {
	var authResp models.WatcherAuthResponse

	u := fmt.Sprintf("%s/watchers/login", s.client.URLPrefix)

	req, err := s.client.PrepareRequest(ctx, http.MethodPost, u, &auth)
	if err != nil {
		return authResp, nil, err
	}

	resp, err := s.client.Do(ctx, req, &authResp)
	if err != nil {
		return authResp, resp, err
	}

	return authResp, resp, nil
}

func (s *AuthService) EnrollWatcher(ctx context.Context, enrollKey string, name string, tags []string, overwrite bool) (*Response, error) {
	u := fmt.Sprintf("%s/watchers/enroll", s.client.URLPrefix)

	req, err := s.client.PrepareRequest(ctx, http.MethodPost, u, &enrollRequest{EnrollKey: enrollKey, Name: name, Tags: tags, Overwrite: overwrite})
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}

	return resp, nil
}
