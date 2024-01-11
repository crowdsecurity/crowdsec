package dumps

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/enescakir/emoji"
	"github.com/fatih/color"
	diff "github.com/r3labs/diff/v2"
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

func DumpTree(parserResults ParserResults, bucketPour BucketPourInfo, opts DumpOpts) {
	//note : we can use line -> time as the unique identifier (of acquisition)
	state := make(map[time.Time]map[string]map[string]ParserResult)
	assoc := make(map[time.Time]string, 0)
	parser_order := make(map[string][]string)

	for stage, parsers := range parserResults {
		//let's process parsers in the order according to idx
		parser_order[stage] = make([]string, len(parsers))
		for pname, parser := range parsers {
			if len(parser) > 0 {
				parser_order[stage][parser[0].Idx-1] = pname
			}
		}

		for _, parser := range parser_order[stage] {
			results := parsers[parser]
			for _, parserRes := range results {
				evt := parserRes.Evt
				if _, ok := state[evt.Line.Time]; !ok {
					state[evt.Line.Time] = make(map[string]map[string]ParserResult)
					assoc[evt.Line.Time] = evt.Line.Raw
				}

				if _, ok := state[evt.Line.Time][stage]; !ok {
					state[evt.Line.Time][stage] = make(map[string]ParserResult)
				}

				state[evt.Line.Time][stage][parser] = ParserResult{Evt: evt, Success: parserRes.Success}
			}
		}
	}

	for bname, evtlist := range bucketPour {
		for _, evt := range evtlist {
			if evt.Line.Raw == "" {
				continue
			}

			//it might be bucket overflow being reprocessed, skip this
			if _, ok := state[evt.Line.Time]; !ok {
				state[evt.Line.Time] = make(map[string]map[string]ParserResult)
				assoc[evt.Line.Time] = evt.Line.Raw
			}

			//there is a trick : to know if an event successfully exit the parsers, we check if it reached the pour() phase
			//we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if _, ok := state[evt.Line.Time]["buckets"]; !ok {
				state[evt.Line.Time]["buckets"] = make(map[string]ParserResult)
			}

			state[evt.Line.Time]["buckets"][bname] = ParserResult{Success: true}
		}
	}

	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	whitelistReason := ""
	//get each line
	for tstamp, rawstr := range assoc {
		if opts.SkipOk {
			if _, ok := state[tstamp]["buckets"]["OK"]; ok {
				continue
			}
		}

		fmt.Printf("line: %s\n", rawstr)

		skeys := make([]string, 0, len(state[tstamp]))

		for k := range state[tstamp] {
			//there is a trick : to know if an event successfully exit the parsers, we check if it reached the pour() phase
			//we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if k == "buckets" {
				continue
			}

			skeys = append(skeys, k)
		}

		sort.Strings(skeys)

		// iterate stage
		var prevItem types.Event

		for _, stage := range skeys {
			parsers := state[tstamp][stage]

			sep := "├"
			presep := "|"

			fmt.Printf("\t%s %s\n", sep, stage)

			//pkeys := sortedMapKeys(parsers)

			for idx, parser := range parser_order[stage] {
				res := parsers[parser].Success
				sep := "├"

				if idx == len(parser_order[stage])-1 {
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

							if change.Path[0] == "Whitelisted" && change.To == true {
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
					if len(changeStr) > 0 {
						changeStr += " "
					}

					changeStr += yellow(fmt.Sprintf("~%d", updated))
				}

				if deleted > 0 {
					if len(changeStr) > 0 {
						changeStr += " "
					}

					changeStr += red(fmt.Sprintf("-%d", deleted))
				}

				if whitelisted {
					if len(changeStr) > 0 {
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

		if len(state[tstamp]["buckets"]) > 0 {
			sep = "├"
		}

		//did the event enter the bucket pour phase ?
		if _, ok := state[tstamp]["buckets"]["OK"]; ok {
			fmt.Printf("\t%s-------- parser success %s\n", sep, emoji.GreenCircle)
		} else if whitelistReason != "" {
			fmt.Printf("\t%s-------- parser success, ignored by whitelist (%s) %s\n", sep, whitelistReason, emoji.GreenCircle)
		} else {
			fmt.Printf("\t%s-------- parser failure %s\n", sep, emoji.RedCircle)
		}

		//now print bucket info
		if len(state[tstamp]["buckets"]) > 0 {
			fmt.Printf("\t├ Scenarios\n")
		}

		bnames := make([]string, 0, len(state[tstamp]["buckets"]))

		for k := range state[tstamp]["buckets"] {
			//there is a trick : to know if an event successfully exit the parsers, we check if it reached the pour() phase
			//we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
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
