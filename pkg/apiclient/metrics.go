package apiclient

type MetricsService service

/*func (s *MetricsService) Add(ctx context.Context, metrics *models.Metrics) (*models.AddMetricsResponse, *Response, error) {

	var metricsResponse models.AddMetricsResponse

	u := "v1/metrics/"
	req, err := s.client.NewRequest("POST", u, &metrics)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &metricsResponse)
	if err != nil {
		return nil, resp, err
	}
	return &metricsResponse, resp, nil
}
*/
