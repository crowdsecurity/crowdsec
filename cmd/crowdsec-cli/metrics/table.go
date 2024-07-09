package metrics

import (
	"errors"
	"sort"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

// ErrNilTable means a nil pointer was passed instead of a table instance. This is a programming error.
var ErrNilTable = errors.New("nil table")

func lapiMetricsToTable(t *cstable.Table, stats map[string]map[string]map[string]int) int {
	// stats: machine -> route -> method -> count
	// sort keys to keep consistent order when printing
	machineKeys := []string{}
	for k := range stats {
		machineKeys = append(machineKeys, k)
	}

	sort.Strings(machineKeys)

	numRows := 0

	for _, machine := range machineKeys {
		// oneRow: route -> method -> count
		machineRow := stats[machine]
		for routeName, route := range machineRow {
			for methodName, count := range route {
				row := []string{
					machine,
					routeName,
					methodName,
				}
				if count != 0 {
					row = append(row, strconv.Itoa(count))
				} else {
					row = append(row, "-")
				}

				t.AddRow(row...)

				numRows++
			}
		}
	}

	return numRows
}

func wlMetricsToTable(t *cstable.Table, stats map[string]map[string]map[string]int, noUnit bool) (int, error) {
	if t == nil {
		return 0, ErrNilTable
	}

	numRows := 0

	for _, name := range maptools.SortedKeys(stats) {
		for _, reason := range maptools.SortedKeys(stats[name]) {
			row := []string{
				name,
				reason,
				"-",
				"-",
			}

			for _, action := range maptools.SortedKeys(stats[name][reason]) {
				value := stats[name][reason][action]

				switch action {
				case "whitelisted":
					row[3] = strconv.Itoa(value)
				case "hits":
					row[2] = strconv.Itoa(value)
				default:
					log.Debugf("unexpected counter '%s' for whitelists = %d", action, value)
				}
			}

			t.AddRow(row...)

			numRows++
		}
	}

	return numRows, nil
}

func metricsToTable(t *cstable.Table, stats map[string]map[string]int, keys []string, noUnit bool) (int, error) {
	if t == nil {
		return 0, ErrNilTable
	}

	numRows := 0

	for _, alabel := range maptools.SortedKeys(stats) {
		astats, ok := stats[alabel]
		if !ok {
			continue
		}

		row := []string{
			alabel,
		}

		for _, sl := range keys {
			if v, ok := astats[sl]; ok && v != 0 {
				row = append(row, formatNumber(int64(v), !noUnit))
			} else {
				row = append(row, "-")
			}
		}

		t.AddRow(row...)

		numRows++
	}

	return numRows, nil
}
