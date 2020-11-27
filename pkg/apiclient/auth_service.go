package apiclient

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// type ApiAlerts service

type AuthService service

func (s *AuthService) UnregisterWatcher(ctx context.Context) (*Response, error) {

	u := fmt.Sprintf("%s/watchers", s.client.URLPrefix)
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

func (s *AuthService) RegisterWatcher(ctx context.Context, registration models.WatcherRegistrationRequest) (*Response, error) {

	u := fmt.Sprintf("%s/watchers", s.client.URLPrefix)

	req, err := s.client.NewRequest("POST", u, &registration)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func (s *AuthService) AuthenticateWatcher(ctx context.Context, auth models.WatcherAuthRequest) (*Response, error) {
	u := fmt.Sprintf("%s/watchers/login", s.client.URLPrefix)
	req, err := s.client.NewRequest("POST", u, &auth)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}
	return resp, nil
}
