package apiclient

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type MetricsService service

func (s *MetricsService) Add(ctx context.Context, metrics *models.Metrics) (interface{}, *Response, error) {
	var response interface{}

	u := fmt.Sprintf("%s/metrics/", s.client.URLPrefix)
	req, err := s.client.NewRequest("POST", u, &metrics)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &response)
	if err != nil {
		return nil, resp, err
	}
	return &response, resp, nil
}
