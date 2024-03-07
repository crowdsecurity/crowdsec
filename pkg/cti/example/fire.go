package main

/*

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cti"
)

func float32ptr(f float32) *float32 {
	return &f
}

func main() {
	client, err := cti.NewCTIClient(os.Getenv("CTI_API_KEY"))
	if err != nil {
		panic(err)
	}
	params := &cti.GetFireParams{
		Page: float32ptr(1),
	}

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
		httpResp, err := client.GetFireWithResponse(context.Background(), params)
		if err != nil {
			panic(err)
		}

		if httpResp.HTTPResponse.StatusCode != 200 {
			panic(fmt.Errorf("unexpected status code %d", httpResp.HTTPResponse.StatusCode))
		}

		resp := httpResp.JSON200

		for _, item := range resp.Items {
			if *item.State == cti.Refused {
				continue
			}
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

*/
