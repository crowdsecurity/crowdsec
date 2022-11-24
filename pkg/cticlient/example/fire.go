package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

func intPtr(i int) *int {
	return &i
}

func main() {
	client := cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(os.Getenv("CTI_API_KEY")))
	paginator := cticlient.NewFirePaginator(client, cticlient.FireParams{
		Limit: intPtr(1000),
	})

	csvHeader := []string{
		"value",
		"reason",
		"type",
		"scope",
		"duration",
	}
	csvFile, err := os.Create("fire.csv")
	if err != nil {
		panic(err)
	}
	defer csvFile.Close()
	csvWriter := csv.NewWriter(csvFile)
	allItems := make([][]string, 0)

	for {
		items, err := paginator.Next()
		if err != nil {
			panic(err)
		}
		if items == nil {
			break
		}

		for _, item := range items {
			banDuration := time.Until(item.Expiration.Time)
			allItems = append(allItems, []string{
				item.Ip,
				"fire-import",
				"ban",
				"ip",
				fmt.Sprintf("%ds", int(banDuration.Seconds())),
			})
		}
	}
	csvWriter.Write(csvHeader)
	csvWriter.WriteAll(allItems)
}
