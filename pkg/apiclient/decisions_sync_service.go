package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type DecisionDeleteService service

// DecisionDeleteService purposely reuses AddSignalsRequestItemDecisions model
func (d *DecisionDeleteService) Add(ctx context.Context, deletedDecisions *models.DecisionsDeleteRequest) (interface{}, *Response, error) {
	var response interface{}
	u := fmt.Sprintf("%s/decisions/delete", d.client.URLPrefix)
	req, err := d.client.NewRequest(http.MethodPost, u, &deletedDecisions)
	if err != nil {
		return nil, nil, errors.Wrap(err, "while building request")
	}

	resp, err := d.client.Do(ctx, req, &response)
	if err != nil {
		return nil, resp, errors.Wrap(err, "while performing request")
	}
	if resp.Response.StatusCode != http.StatusOK {
		log.Warnf("Decisions delete response : http %s", resp.Response.Status)
	} else {
		log.Debugf("Decisions delete response : http %s", resp.Response.Status)
	}
	return &response, resp, nil
}
