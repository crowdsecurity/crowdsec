package apiclient

import (
	"context"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type DecisionDeleteService service

// DecisionDeleteService purposely reuses AddSignalsRequestItemDecisions model
func (d *DecisionDeleteService) Add(ctx context.Context, deletedDecisions *models.DecisionsDeleteRequest) (interface{}, *Response, error) {
	var response interface{}

	u := fmt.Sprintf("%s/decisions/delete", d.client.URLPrefix)

	req, err := d.client.NewRequest(http.MethodPost, u, &deletedDecisions)
	if err != nil {
		return nil, nil, fmt.Errorf("while building request: %w", err)
	}

	resp, err := d.client.Do(ctx, req, &response)
	if err != nil {
		return nil, resp, fmt.Errorf("while performing request: %w", err)
	}

	if resp.Response.StatusCode != http.StatusOK {
		log.Warnf("Decisions delete response : http %s", resp.Response.Status)
	} else {
		log.Debugf("Decisions delete response : http %s", resp.Response.Status)
	}

	return &response, resp, nil
}
