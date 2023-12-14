package apiclient

import (
	"context"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type SignalService service

func (s *SignalService) Add(ctx context.Context, signals *models.AddSignalsRequest) (interface{}, *Response, error) {
	var response interface{}

	u := fmt.Sprintf("%s/signals", s.client.URLPrefix)

	req, err := s.client.NewRequest(http.MethodPost, u, &signals)
	if err != nil {
		return nil, nil, fmt.Errorf("while building request: %w", err)
	}

	resp, err := s.client.Do(ctx, req, &response)
	if err != nil {
		return nil, resp, fmt.Errorf("while performing request: %w", err)
	}

	if resp.Response.StatusCode != http.StatusOK {
		log.Warnf("Signal push response : http %s", resp.Response.Status)
	} else {
		log.Debugf("Signal push response : http %s", resp.Response.Status)
	}

	return &response, resp, nil
}
