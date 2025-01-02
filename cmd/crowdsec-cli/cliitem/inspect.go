package cliitem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func inspectItem(hub *cwhub.Hub, item *cwhub.Item, wantMetrics bool, output string, prometheusURL string, wantColor string) error {
	// This is dirty...
	// We want to show current dependencies (from content), not latest (from index).
	// The item is modifed but after this function the whole hub should be thrown away.
	// A cleaner way would be to copy the struct first.
	item.Dependencies = item.CurrentDependencies()

	switch output {
	case "human", "raw":
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)

		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("unable to encode item: %w", err)
		}
	case "json":
		b, err := json.MarshalIndent(*item, "", "  ")
		if err != nil {
			return fmt.Errorf("unable to serialize item: %w", err)
		}

		fmt.Print(string(b))
	}

	if output != "human" {
		return nil
	}

	if item.State.Tainted {
		fmt.Println()
		fmt.Printf(`This item is tainted. Use "%s %s inspect --diff %s" to see why.`, filepath.Base(os.Args[0]), item.Type, item.Name)
		fmt.Println()
	}

	if wantMetrics {
		fmt.Printf("\nCurrent metrics: \n")

		if err := showMetrics(prometheusURL, hub, item, wantColor); err != nil {
			return err
		}
	}

	return nil
}
