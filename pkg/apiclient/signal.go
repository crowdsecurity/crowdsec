package apiclient

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Signal struct {
	Message         string         `json:"message"`
	Scenario        string         `json:"scenario"`
	ScenarioHash    string         `json:"scenario_hash"`
	ScenarioVersion string         `json:"scenario_version"`
	Source          *models.Source `json:"source"`
	StartAt         string         `json:"start_at"`
	StopAt          string         `json:"stop_at"`
	MachineID       string         `json:"machine_id"`
	CreatedAt       string         `json:"created_at"`
}

type SignalService service

func (s *SignalService) Add(ctx context.Context, signals []*Signal) (interface{}, *Response, error) {
	var response interface{}

	u := fmt.Sprintf("%s/signals", s.client.URLPrefix)
	req, err := s.client.NewRequest("POST", u, &signals)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &response)
	if err != nil {
		return nil, resp, err
	}

	return &response, resp, nil
}
