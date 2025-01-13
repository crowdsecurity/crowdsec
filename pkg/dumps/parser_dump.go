package dumps

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	diff "github.com/r3labs/diff/v2"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type ParserResult struct {
	Idx     int
	Evt     types.Event
	Success bool
}

type ParserResults map[string]map[string][]ParserResult

type DumpOpts struct {
	Details          bool
	SkipOk           bool
	ShowNotOkParsers bool
}

func LoadParserDump(filepath string) (*ParserResults, error) {
	dumpData, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer dumpData.Close()

	results, err := io.ReadAll(dumpData)
	if err != nil {
		return nil, err
	}

	pdump := ParserResults{}

	if err := yaml.Unmarshal(results, &pdump); err != nil {
		return nil, err
	}

	/* we know that some variables should always be set,
	let's check if they're present in last parser output of last stage */

	stages := maptools.SortedKeys(pdump)

	var lastStage string

	// Loop over stages to find last successful one with at least one parser
	for i := len(stages) - 2; i >= 0; i-- {
		if len(pdump[stages[i]]) != 0 {
			lastStage = stages[i]
			break
		}
	}

	parsers := make([]string, 0, len(pdump[lastStage]))

	for k := range pdump[lastStage] {
		parsers = append(parsers, k)
	}

	sort.Strings(parsers)

	if len(parsers) == 0 {
		return nil, errors.New("no parser found. Please install the appropriate parser and retry")
	}

	lastParser := parsers[len(parsers)-1]

	for idx, result := range pdump[lastStage][lastParser] {
		if result.Evt.StrTime == "" {
			log.Warningf("Line %d/%d is missing evt.StrTime. It is most likely a mistake as it will prevent your logs to be processed in time-machine/forensic mode.", idx, len(pdump[lastStage][lastParser]))
		} else {
			log.Debugf("Line %d/%d has evt.StrTime set to '%s'", idx, len(pdump[lastStage][lastParser]), result.Evt.StrTime)
		}
	}

	return &pdump, nil
}

type tree struct {
	// note : we can use line -> time as the unique identifier (of acquisition)
	state       map[time.Time]map[string]map[string]ParserResult
	assoc       map[time.Time]string
	parserOrder map[string][]string
}

func newTree() *tree {
	return &tree{
		state:       make(map[time.Time]map[string]map[string]ParserResult),
		assoc:       make(map[time.Time]string),
		parserOrder: make(map[string][]string),
	}
}

func DumpTree(parserResults ParserResults, bucketPour BucketPourInfo, opts DumpOpts) {
	t := newTree()
	t.processEvents(parserResults)
	t.processBuckets(bucketPour)
	t.displayResults(opts)
}

func (t *tree) processEvents(parserResults ParserResults) {
	for stage, parsers := range parserResults {
		// let's process parsers in the order according to idx
		t.parserOrder[stage] = make([]string, len(parsers))

		for pname, parser := range parsers {
			if len(parser) > 0 {
				t.parserOrder[stage][parser[0].Idx-1] = pname
			}
		}

		for _, parser := range t.parserOrder[stage] {
			results := parsers[parser]
			for _, parserRes := range results {
				evt := parserRes.Evt
				if _, ok := t.state[evt.Line.Time]; !ok {
					t.state[evt.Line.Time] = make(map[string]map[string]ParserResult)
					t.assoc[evt.Line.Time] = evt.Line.Raw
				}

				if _, ok := t.state[evt.Line.Time][stage]; !ok {
					t.state[evt.Line.Time][stage] = make(map[string]ParserResult)
				}

				t.state[evt.Line.Time][stage][parser] = ParserResult{Evt: evt, Success: parserRes.Success}
			}
		}
	}
}

func (t *tree) processBuckets(bucketPour BucketPourInfo) {
	for bname, events := range bucketPour {
		for i := range events {
			if events[i].Line.Raw == "" {
				continue
			}

			// it might be bucket overflow being reprocessed, skip this
			if _, ok := t.state[events[i].Line.Time]; !ok {
				t.state[events[i].Line.Time] = make(map[string]map[string]ParserResult)
				t.assoc[events[i].Line.Time] = events[i].Line.Raw
			}

			// there is a trick: to know if an event successfully exit the parsers, we check if it reached the pour() phase
			// we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if _, ok := t.state[events[i].Line.Time]["buckets"]; !ok {
				t.state[events[i].Line.Time]["buckets"] = make(map[string]ParserResult)
			}

			t.state[events[i].Line.Time]["buckets"][bname] = ParserResult{Success: true}
		}
	}
}

func (t *tree) displayResults(opts DumpOpts) {
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	whitelistReason := ""

	// get each line
	for tstamp, rawstr := range t.assoc {
		if opts.SkipOk {
			if _, ok := t.state[tstamp]["buckets"]["OK"]; ok {
				continue
			}
		}

		fmt.Printf("line: %s\n", rawstr)

		skeys := make([]string, 0, len(t.state[tstamp]))

		for k := range t.state[tstamp] {
			// there is a trick : to know if an event successfully exit the parsers, we check if it reached the pour() phase
			// we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if k == "buckets" {
				continue
			}

			skeys = append(skeys, k)
		}

		sort.Strings(skeys)

		// iterate stage
		var prevItem types.Event

		for _, stage := range skeys {
			parsers := t.state[tstamp][stage]

			sep := "├"
			presep := "|"

			fmt.Printf("\t%s %s\n", sep, stage)

			for idx, parser := range t.parserOrder[stage] {
				res := parsers[parser].Success
				sep := "├"

				if idx == len(t.parserOrder[stage])-1 {
					sep = "└"
				}

				created := 0
				updated := 0
				deleted := 0
				whitelisted := false
				changeStr := ""
				detailsDisplay := ""

				if res {
					changelog, _ := diff.Diff(prevItem, parsers[parser].Evt)
					for _, change := range changelog {
						switch change.Type {
						case "create":
							created++

							detailsDisplay += fmt.Sprintf("\t%s\t\t%s %s evt.%s : %s\n", presep, sep, change.Type, strings.Join(change.Path, "."), green(change.To))
						case "update":
							detailsDisplay += fmt.Sprintf("\t%s\t\t%s %s evt.%s : %s -> %s\n", presep, sep, change.Type, strings.Join(change.Path, "."), change.From, yellow(change.To))

							if change.Path[0] == "Whitelisted" && change.To == true { //nolint:revive
								whitelisted = true

								if whitelistReason == "" {
									whitelistReason = parsers[parser].Evt.WhitelistReason
								}
							}

							updated++
						case "delete":
							deleted++

							detailsDisplay += fmt.Sprintf("\t%s\t\t%s %s evt.%s\n", presep, sep, change.Type, red(strings.Join(change.Path, ".")))
						}
					}

					prevItem = parsers[parser].Evt
				}

				if created > 0 {
					changeStr += green(fmt.Sprintf("+%d", created))
				}

				if updated > 0 {
					if changeStr != "" {
						changeStr += " "
					}

					changeStr += yellow(fmt.Sprintf("~%d", updated))
				}

				if deleted > 0 {
					if changeStr != "" {
						changeStr += " "
					}

					changeStr += red(fmt.Sprintf("-%d", deleted))
				}

				if whitelisted {
					if changeStr != "" {
						changeStr += " "
					}

					changeStr += red("[whitelisted]")
				}

				if changeStr == "" {
					changeStr = yellow("unchanged")
				}

				if res {
					fmt.Printf("\t%s\t%s %s %s (%s)\n", presep, sep, emoji.GreenCircle, parser, changeStr)

					if opts.Details {
						fmt.Print(detailsDisplay)
					}
				} else if opts.ShowNotOkParsers {
					fmt.Printf("\t%s\t%s %s %s\n", presep, sep, emoji.RedCircle, parser)
				}
			}
		}

		sep := "└"

		if len(t.state[tstamp]["buckets"]) > 0 {
			sep = "├"
		}

		// did the event enter the bucket pour phase ?
		if _, ok := t.state[tstamp]["buckets"]["OK"]; ok {
			fmt.Printf("\t%s-------- parser success %s\n", sep, emoji.GreenCircle)
		} else if whitelistReason != "" {
			fmt.Printf("\t%s-------- parser success, ignored by whitelist (%s) %s\n", sep, whitelistReason, emoji.GreenCircle)
		} else {
			fmt.Printf("\t%s-------- parser failure %s\n", sep, emoji.RedCircle)
		}

		// now print bucket info
		if len(t.state[tstamp]["buckets"]) > 0 {
			fmt.Printf("\t├ Scenarios\n")
		}

		bnames := make([]string, 0, len(t.state[tstamp]["buckets"]))

		for k := range t.state[tstamp]["buckets"] {
			// there is a trick : to know if an event successfully exit the parsers, we check if it reached the pour() phase
			// we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if k == "OK" {
				continue
			}

			bnames = append(bnames, k)
		}

		sort.Strings(bnames)

		for idx, bname := range bnames {
			sep := "├"
			if idx == len(bnames)-1 {
				sep = "└"
			}

			fmt.Printf("\t\t%s %s %s\n", sep, emoji.GreenCircle, bname)
		}

		fmt.Println()
	}
}
