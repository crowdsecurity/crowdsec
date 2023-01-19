package cticlient

type FirePaginator struct {
	client      *CrowdsecCTIClient
	params      FireParams
	currentPage int
	done        bool
}

func (p *FirePaginator) Next() ([]FireItem, error) {
	if p.done {
		return nil, nil
	}
	p.params.Page = &p.currentPage
	resp, err := p.client.Fire(p.params)
	if err != nil {
		return nil, err
	}
	p.currentPage++
	if resp.Links.Next == nil {
		p.done = true
	}
	return resp.Items, nil
}

func NewFirePaginator(client *CrowdsecCTIClient, params FireParams) *FirePaginator {
	startPage := 1
	if params.Page != nil {
		startPage = *params.Page
	}
	return &FirePaginator{
		client:      client,
		params:      params,
		currentPage: startPage,
	}
}
