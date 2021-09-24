package cstest

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type parserResult struct {
	Evt     types.Event
	Success bool
}
type ParserResults map[string]map[string][]parserResult

func LoadParserDump(filepath string) (map[string]map[string][]parserResult, error) {
	var pdump ParserResults

	data_fd, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer data_fd.Close()
	//umarshal full gruik
	results, err := ioutil.ReadAll(data_fd)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(results, &pdump); err != nil {
		return nil, err
	}
	return pdump, nil
}

func DumpParserTree(parser_results ParserResults) error {
	//note : we can use line -> time as the unique identifier (of acquisition)

	var state map[time.Time]map[string]map[string]bool = make(map[time.Time]map[string]map[string]bool, 0)
	var assoc map[time.Time]string = make(map[time.Time]string, 0)

	for stage, parsers := range parser_results {
		log.Printf("stage : %s", stage)
		for parser, results := range parsers {
			log.Printf("parser : %s", parser)
			for _, parser_res := range results {
				evt := parser_res.Evt
				if _, ok := state[evt.Line.Time]; !ok {
					state[evt.Line.Time] = make(map[string]map[string]bool, 0)
					assoc[evt.Line.Time] = evt.Line.Raw
				}
				if _, ok := state[evt.Line.Time][stage]; !ok {
					state[evt.Line.Time][stage] = make(map[string]bool, 0)
				}
				state[evt.Line.Time][stage][parser] = parser_res.Success
			}
		}
	}

	//get each line
	for tstamp, rawstr := range assoc {
		fmt.Printf("line:%s\n", rawstr)
		skeys := make([]string, 0, len(state[tstamp]))
		for k := range state[tstamp] {
			skeys = append(skeys, k)
		}
		sort.Strings(skeys)
		//iterate stage
		for idx, stage := range skeys {
			parsers := state[tstamp][stage]

			sep := "├"
			presep := "|"
			if idx == len(skeys)-1 {
				sep = "└"
				presep = ""
			}
			fmt.Printf("\t%s %s\n", sep, stage)

			pkeys := make([]string, 0, len(parsers))
			for k := range parsers {
				pkeys = append(pkeys, k)
			}
			sort.Strings(pkeys)

			for idx, parser := range pkeys {
				res := parsers[parser]
				sep := "├"
				if idx == len(pkeys)-1 {
					sep = "└"
				}
				if res {
					fmt.Printf("\t%s\t%s %s %s\n", presep, sep, emoji.GreenCircle, parser)
				} else {
					fmt.Printf("\t%s\t%s %s %s\n", presep, sep, emoji.RedCircle, parser)

				}
			}
		}

	}
	return nil
}
