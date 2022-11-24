package main

import (
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

func intPtr(i int) *int {
	return &i
}

func main() {
	client := cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(os.Getenv("CTI_API_KEY")))
	paginator := cticlient.NewFirePaginator(client, cticlient.FireParams{
		Limit: intPtr(1),
	})

	for {
		items, err := paginator.Next()
		if err != nil {
			panic(err)
		}
		if items == nil {
			break
		}

		fmt.Printf("Got %d items\n", len(items))
	}
}
