package cstest

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
)

type ParserCoverage struct {
	Parser      string
	Tests_count int
	Present_in  map[string]bool //poorman's set
}

func (h *HubTest) GetParsersCoverage() ([]ParserCoverage, error) {
	var coverage []ParserCoverage
	if _, ok := h.HubIndex.Data[cwhub.PARSERS]; !ok {
		log.Fatalf("no parsers in hub index")
	}
	//populate from hub, iterate in alphabetical order
	var pkeys []string
	for pname := range h.HubIndex.Data[cwhub.PARSERS] {
		pkeys = append(pkeys, pname)
	}
	sort.Strings(pkeys)
	for _, pname := range pkeys {
		coverage = append(coverage, ParserCoverage{
			Parser:      pname,
			Tests_count: 0,
			Present_in:  make(map[string]bool),
		})
	}

	//parser the expressions a-la-oneagain
	passerts, err := filepath.Glob(".tests/*/parser.assert")
	if err != nil {
		log.Fatalf("while find parser asserts : %s", err)
	}
	for _, assert := range passerts {
		file, err := os.Open(assert)
		if err != nil {
			log.Fatalf("while reading %s : %s", assert, err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			assertLine := regexp.MustCompile(`^results\["[^"]+"\]\["(?P<scenario>[^"]+)"\]\[[0-9]+\]\.Evt\..*`)
			line := scanner.Text()
			log.Debugf("assert line : %s", line)
			match := assertLine.FindStringSubmatch(line)
			if len(match) == 0 {
				log.Debugf("%s doesn't match", line)
				continue
			}
			sidx := assertLine.SubexpIndex("scenario")
			scanner_name := match[sidx]
			for idx, pcover := range coverage {
				if pcover.Parser == scanner_name {
					coverage[idx].Tests_count++
					coverage[idx].Present_in[assert] = true
				}
			}
		}
		file.Close()
	}
	return coverage, nil
}
