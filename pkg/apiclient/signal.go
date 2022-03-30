package apiclient

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
)

type SignalService service

func (s *SignalService) Add(ctx context.Context, signals *models.AddSignalsRequest) (interface{}, *Response, error) {
	var response interface{}

	u := fmt.Sprintf("%s/signals", s.client.URLPrefix)
	req, err := s.client.NewRequest("POST", u, &signals)
	if err != nil {
		return nil, nil, errors.Wrap(err, "while building request")
	}

	resp, err := s.client.Do(ctx, req, &response)
	if err != nil {
		return nil, resp, errors.Wrap(err, "while performing request")
	}
	if resp.Response.StatusCode != 200 {
		log.Warnf("Signal push response : http %s", resp.Response.Status)
	} else {
		log.Debugf("Signal push response : http %s", resp.Response.Status)
	}
	return &response, resp, nil
}
